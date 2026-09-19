package controlplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apiv1 "github.com/danthegoodman1/vbuckets/api/v1"
	"github.com/danthegoodman1/vbuckets/http_server"
	"github.com/danthegoodman1/vbuckets/iam"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func readyTestClient(revision uint64) *Client {
	c := NewClient("test-control-plane", zerolog.Nop())
	c.state, c.revision, c.cursor = StateReady, revision, fmt.Sprintf("cursor-%d", revision)
	c.barrierRequired = false
	return c
}

func TestClientOptionsClampReconnectMaximumToMinimum(t *testing.T) {
	options := defaultClientOptions()
	options.ReconnectMinBackoff = 45 * time.Second
	options.ReconnectMaxBackoff = 0
	c := NewClientWithOptions("test", zerolog.Nop(), options)
	require.Equal(t, 45*time.Second, c.opts.ReconnectMaxBackoff)
}

func TestReadinessSnapshotCoversEveryLifecycleState(t *testing.T) {
	for _, state := range []State{StateStartup, StateConnecting, StateSynchronizing, StateReady, StateDisconnected, StateShutdown} {
		t.Run(string(state), func(t *testing.T) {
			c := NewClient("test", zerolog.Nop())
			c.syncMu.Lock()
			c.transitionLocked(state)
			c.barrierRequired = state != StateReady
			c.syncMu.Unlock()
			snapshot := c.ReadinessSnapshot()
			require.Equal(t, string(state), snapshot.State)
			require.Equal(t, state == StateReady, snapshot.Ready)
			require.Equal(t, state != StateReady, snapshot.BarrierRequired)
		})
	}
}

func credentialInvalidation(revision uint64, key string) *apiv1.WatchEvent {
	return &apiv1.WatchEvent{Revision: revision, Cursor: fmt.Sprintf("cursor-%d", revision), Event: &apiv1.WatchEvent_Credentials{Credentials: &apiv1.CredentialsDelta{AccessKeyId: key}}}
}

func vbucketInvalidation(revision uint64, key, bucket string) *apiv1.WatchEvent {
	return &apiv1.WatchEvent{Revision: revision, Cursor: fmt.Sprintf("cursor-%d", revision), Event: &apiv1.WatchEvent_Vbucket{Vbucket: &apiv1.VBucketDelta{AccessKeyId: key, BucketName: bucket}}}
}

func barrier(revision uint64) *apiv1.WatchEvent {
	return &apiv1.WatchEvent{Revision: revision, Cursor: fmt.Sprintf("cursor-%d", revision), Event: &apiv1.WatchEvent_SynchronizationBarrier{SynchronizationBarrier: &apiv1.SynchronizationBarrier{}}}
}

func TestWatchStateSnapshotBarrierAndProtocolFaults(t *testing.T) {
	c := NewClient("test-control-plane", zerolog.Nop())
	c.state = StateSynchronizing
	require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 3, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}))
	require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 3, Event: &apiv1.WatchEvent_BaseHost{BaseHost: &apiv1.BaseHostDelta{BaseHost: "s3.example.com"}}}))
	_, _, err := c.LookupBaseHost(context.Background(), "bucket.s3.example.com")
	require.ErrorIs(t, err, ErrUnsynchronized, "a partial snapshot must never be visible")
	require.NoError(t, c.processWatch(barrier(3)))
	require.True(t, c.Ready())

	require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 3, Cursor: "cursor-3", Event: &apiv1.WatchEvent_Heartbeat{Heartbeat: &apiv1.Heartbeat{}}}))
	err = c.processWatch(credentialInvalidation(3, "key"))
	require.Error(t, err, "duplicate mutation pairs are protocol-fatal")
	require.False(t, c.Ready())

	// Frames already buffered on the invalidated stream cannot restore ready.
	err = c.processWatch(barrier(3))
	require.ErrorIs(t, err, ErrUnsynchronized)
	require.False(t, c.Ready())
}

func TestWatchGapRollbackNestedAndSnapshotBoundsFailClosed(t *testing.T) {
	t.Run("gap", func(t *testing.T) {
		c := readyTestClient(5)
		require.Error(t, c.processWatch(credentialInvalidation(7, "key")))
		require.Equal(t, uint64(1), c.Stats().WatchGaps)
		require.False(t, c.Ready())
	})
	t.Run("rollback", func(t *testing.T) {
		c := readyTestClient(5)
		c.state = StateSynchronizing
		require.Error(t, c.processWatch(&apiv1.WatchEvent{Revision: 4, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}))
		require.False(t, c.Ready())
	})
	t.Run("nested", func(t *testing.T) {
		c := readyTestClient(5)
		c.state = StateSynchronizing
		require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 6, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}))
		require.Error(t, c.processWatch(&apiv1.WatchEvent{Revision: 6, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}))
	})
	t.Run("bound", func(t *testing.T) {
		c := readyTestClient(1)
		c.state, c.baseHostMax = StateSynchronizing, 1
		require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 2, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}))
		require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 2, Event: &apiv1.WatchEvent_BaseHost{BaseHost: &apiv1.BaseHostDelta{BaseHost: "s3.example.com"}}}))
		require.Error(t, c.processWatch(&apiv1.WatchEvent{Revision: 2, Event: &apiv1.WatchEvent_BaseHost{BaseHost: &apiv1.BaseHostDelta{BaseHost: "s3.example.net"}}}))
	})
	t.Run("same revision changed cursor", func(t *testing.T) {
		c := readyTestClient(5)
		c.state = StateSynchronizing
		require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 5, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}))
		changed := barrier(5)
		changed.Cursor = "different-cursor"
		require.Error(t, c.processWatch(changed))
		require.False(t, c.Ready())
	})
	t.Run("heartbeat mismatch", func(t *testing.T) {
		c := readyTestClient(5)
		require.Error(t, c.processWatch(&apiv1.WatchEvent{Revision: 5, Cursor: "wrong", Event: &apiv1.WatchEvent_Heartbeat{Heartbeat: &apiv1.Heartbeat{}}}))
		require.False(t, c.Ready())
	})
	for name, event := range map[string]*apiv1.WatchEvent{
		"snapshot credential": {Revision: 6, Event: &apiv1.WatchEvent_Credentials{Credentials: &apiv1.CredentialsDelta{AccessKeyId: "key"}}},
		"snapshot vbucket":    {Revision: 6, Event: &apiv1.WatchEvent_Vbucket{Vbucket: &apiv1.VBucketDelta{AccessKeyId: "key", BucketName: "bucket"}}},
		"snapshot removal":    {Revision: 6, Event: &apiv1.WatchEvent_BaseHost{BaseHost: &apiv1.BaseHostDelta{BaseHost: "s3.example.com", Remove: true}}},
	} {
		t.Run(name, func(t *testing.T) {
			c := readyTestClient(5)
			c.state = StateSynchronizing
			require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 6, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}))
			require.Error(t, c.processWatch(event))
			require.False(t, c.Ready())
		})
	}
	t.Run("snapshot duplicate base domain", func(t *testing.T) {
		c := readyTestClient(5)
		c.state = StateSynchronizing
		require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 6, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}))
		entry := &apiv1.WatchEvent{Revision: 6, Event: &apiv1.WatchEvent_BaseHost{BaseHost: &apiv1.BaseHostDelta{BaseHost: "s3.example.com"}}}
		require.NoError(t, c.processWatch(entry))
		require.Error(t, c.processWatch(entry))
		require.False(t, c.Ready())
	})
	t.Run("snapshot wrong barrier revision", func(t *testing.T) {
		c := readyTestClient(5)
		c.state = StateSynchronizing
		require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 6, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}))
		require.Error(t, c.processWatch(barrier(7)))
		require.False(t, c.Ready())
	})
	t.Run("newer snapshot reuses old cursor", func(t *testing.T) {
		c := readyTestClient(5)
		c.state = StateSynchronizing
		require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 6, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}))
		reused := barrier(6)
		reused.Cursor = "cursor-5"
		require.Error(t, c.processWatch(reused))
		require.False(t, c.Ready())
	})
}

func TestReconnectReplayNeverReadiesBeforeBarrier(t *testing.T) {
	c := readyTestClient(5)
	c.requiredRevision = 7
	c.transitionLocked(StateSynchronizing) // live Create catch-up
	c.markUnsynchronized(StateDisconnected)
	c.syncMu.Lock()
	c.transitionLocked(StateSynchronizing) // a new stream has opened
	c.syncMu.Unlock()
	require.NoError(t, c.processWatch(credentialInvalidation(6, "key")))
	require.NoError(t, c.processWatch(vbucketInvalidation(7, "key", "bucket")))
	require.False(t, c.Ready(), "replay reaching the Create target still needs its barrier")
	status := c.Status()
	require.Zero(t, status.RequiredRevision)
	require.True(t, status.BarrierRequired)
	require.NoError(t, c.processWatch(barrier(7)))
	status = c.Status()
	require.True(t, status.Ready)
	require.False(t, status.BarrierRequired)
}

func TestFutureUnaryEvidenceRecordsRequiredRevisionBeforePayloadParsing(t *testing.T) {
	c := newTestClientWithFake(&fakeControlPlaneClient{lookupCredentials: func(context.Context, *apiv1.LookupCredentialsRequest, ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
		return &apiv1.LookupCredentialsResponse{Revision: 12, Found: true, IamPolicyJson: "not-json"}, nil
	}})
	c.revision, c.cursor = 10, "cursor-10"
	_, err := c.LookupCredentials(context.Background(), "key")
	require.ErrorIs(t, err, ErrRevisionRace)
	status := c.Status()
	require.False(t, status.Ready)
	require.Equal(t, uint64(12), status.RequiredRevision)

	// Preserve the healthy stream and highest target, even for malformed
	// future payloads. A lower target cannot shorten or restart catch-up.
	require.Equal(t, StateSynchronizing, c.Status().State)
	require.Empty(t, c.resync)
	started := c.synchronizingSince
	require.ErrorIs(t, c.checkUnaryRevision(11, 10), ErrRevisionRace)
	require.Equal(t, uint64(12), c.Status().RequiredRevision)
	require.Equal(t, started, c.synchronizingSince)
	require.NoError(t, c.processWatch(barrier(10)))
	require.False(t, c.Ready())
	require.NoError(t, c.processWatch(credentialInvalidation(11, "other")))
	require.NoError(t, c.processWatch(credentialInvalidation(12, "other-2")))
	require.True(t, c.Ready())
}

func TestFutureVBucketAndListEvidencePrecedesPayloadParsing(t *testing.T) {
	t.Run("malformed future vbucket", func(t *testing.T) {
		c := newTestClientWithFake(&fakeControlPlaneClient{lookupVBucket: func(context.Context, *apiv1.LookupVBucketRequest, ...grpc.CallOption) (*apiv1.LookupVBucketResponse, error) {
			return &apiv1.LookupVBucketResponse{Revision: 12, Found: true, RealEndpoint: ":// malformed"}, nil
		}})
		c.revision, c.cursor = 10, "cursor-10"
		_, err := c.LookupVBucket(context.Background(), "key", "bucket")
		require.ErrorIs(t, err, ErrRevisionRace)
		require.Equal(t, uint64(12), c.Status().RequiredRevision)
		require.False(t, c.Ready())
	})
	t.Run("malformed future list", func(t *testing.T) {
		c := newTestClientWithFake(&fakeControlPlaneClient{listVBuckets: func(context.Context, *apiv1.ListVBucketsRequest, ...grpc.CallOption) (*apiv1.ListVBucketsResponse, error) {
			return &apiv1.ListVBucketsResponse{Revision: 12, Buckets: []*apiv1.VBucketSummary{nil}}, nil
		}})
		c.revision, c.cursor = 10, "cursor-10"
		_, err := c.ListVBuckets(context.Background(), "key")
		require.ErrorIs(t, err, ErrRevisionRace)
		require.Equal(t, uint64(12), c.Status().RequiredRevision)
		require.False(t, c.Ready())
	})
}

func TestCacheHitLinearizesWithCredentialInvalidationAndRemoval(t *testing.T) {
	t.Run("invalidation reloads", func(t *testing.T) {
		c := newTestClientWithFake(&fakeControlPlaneClient{lookupCredentials: func(_ context.Context, req *apiv1.LookupCredentialsRequest, _ ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
			require.Equal(t, uint64(2), req.MinimumRevision)
			return &apiv1.LookupCredentialsResponse{SecretKey: "new", IamPolicyJson: controlPlaneAllowAllPolicyJSON, Ttl: durationpb.New(time.Minute), Found: true, Revision: 2}, nil
		}})
		c.caches.credentials.Set("key", cachedCredentials{VirtualCredentials: &http_server.VirtualCredentials{SecretKey: "old", IAMPolicy: iam.DenyAllPolicy()}, Found: true, Revision: 1, TTL: time.Minute}, time.Minute)
		read, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		c.afterCacheRead = func() { once.Do(func() { close(read); <-release }) }
		result := make(chan *http_server.VirtualCredentials, 1)
		go func() { creds, _ := c.LookupCredentials(context.Background(), "key"); result <- creds }()
		<-read
		require.NoError(t, c.processWatch(credentialInvalidation(2, "key")))
		close(release)
		require.Equal(t, "new", (<-result).SecretKey)
	})
	t.Run("removal denies", func(t *testing.T) {
		c := newTestClientWithFake(&fakeControlPlaneClient{})
		c.caches.credentials.Set("key", cachedCredentials{VirtualCredentials: &http_server.VirtualCredentials{SecretKey: "old", IAMPolicy: iam.DenyAllPolicy()}, Found: true, Revision: 1, TTL: time.Minute}, time.Minute)
		read, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		c.afterCacheRead = func() { once.Do(func() { close(read); <-release }) }
		errCh := make(chan error, 1)
		go func() { _, lookupErr := c.LookupCredentials(context.Background(), "key"); errCh <- lookupErr }()
		<-read
		require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 2, Cursor: "cursor-2", Event: &apiv1.WatchEvent_Credentials{Credentials: &apiv1.CredentialsDelta{AccessKeyId: "key", Remove: true, NegativeTtl: durationpb.New(time.Minute)}}}))
		close(release)
		require.ErrorIs(t, <-errCh, ErrNotFound)
	})
}

func TestVBucketCacheHitAndListParsingLinearizeWithWatch(t *testing.T) {
	t.Run("vbucket", func(t *testing.T) {
		c := newTestClientWithFake(&fakeControlPlaneClient{lookupVBucket: func(_ context.Context, req *apiv1.LookupVBucketRequest, _ ...grpc.CallOption) (*apiv1.LookupVBucketResponse, error) {
			return validLookupVBucketResponse(req.MinimumRevision, "new-prefix"), nil
		}})
		old, err := http_server.NormalizeVBucketConfig(validVBucketConfig("old-prefix"))
		require.NoError(t, err)
		c.caches.vbuckets.Set(vbucketCacheKey("key", "bucket"), cachedVBucket{VBucketConfig: old, Found: true, Revision: 1, TTL: time.Minute}, time.Minute)
		read, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		c.afterCacheRead = func() { once.Do(func() { close(read); <-release }) }
		result := make(chan *http_server.VBucketConfig, 1)
		go func() { cfg, _ := c.LookupVBucket(context.Background(), "key", "bucket"); result <- cfg }()
		<-read
		require.NoError(t, c.processWatch(vbucketInvalidation(2, "key", "bucket")))
		close(release)
		require.Equal(t, "new-prefix", (<-result).PathPrefix)
	})
	t.Run("list", func(t *testing.T) {
		c := newTestClientWithFake(&fakeControlPlaneClient{listVBuckets: func(context.Context, *apiv1.ListVBucketsRequest, ...grpc.CallOption) (*apiv1.ListVBucketsResponse, error) {
			return &apiv1.ListVBucketsResponse{Revision: 1, Buckets: []*apiv1.VBucketSummary{{BucketName: "bucket", CreationDate: timestamppb.Now()}}}, nil
		}})
		parsed, release := make(chan struct{}), make(chan struct{})
		c.afterListParse = func() { close(parsed); <-release }
		errCh := make(chan error, 1)
		go func() { _, listErr := c.ListVBuckets(context.Background(), "key"); errCh <- listErr }()
		<-parsed
		require.NoError(t, c.processWatch(credentialInvalidation(2, "other")))
		close(release)
		require.ErrorIs(t, <-errCh, ErrRevisionRace)
	})
}

func validVBucketConfig(prefix string) *http_server.VBucketConfig {
	return &http_server.VBucketConfig{RealEndpoint: "https://s3.example.com", RealBucket: "real-bucket", RealAccessKey: "real-access", RealSecretKey: "real-secret", RealRegion: "us-east-1", PathPrefix: prefix, RealUsePathStyle: true, RoutingTokenKey: controlPlaneRoutingTokenKey}
}

func validLookupVBucketResponse(revision uint64, prefix string) *apiv1.LookupVBucketResponse {
	cfg := validVBucketConfig(prefix)
	return &apiv1.LookupVBucketResponse{RealEndpoint: cfg.RealEndpoint, RealBucket: cfg.RealBucket, RealAccessKey: cfg.RealAccessKey, RealSecretKey: cfg.RealSecretKey, RealRegion: cfg.RealRegion, PathPrefix: cfg.PathPrefix, RealUsePathStyle: cfg.RealUsePathStyle, RoutingTokenKey: cfg.RoutingTokenKey, Ttl: durationpb.New(time.Minute), Found: true, Revision: revision}
}

func TestNegativeCachingUnavailableAndColdChurn(t *testing.T) {
	var credentialCalls atomic.Int64
	c := newTestClientWithFake(&fakeControlPlaneClient{lookupCredentials: func(context.Context, *apiv1.LookupCredentialsRequest, ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
		credentialCalls.Add(1)
		return nil, status.Error(codes.Unavailable, "temporary")
	}})
	for range 2 {
		_, err := c.LookupCredentials(context.Background(), "key")
		require.Equal(t, codes.Unavailable, status.Code(err))
	}
	require.Equal(t, int64(2), credentialCalls.Load(), "service failures are never negative-cached")

	for revision := uint64(2); revision < 102; revision++ {
		key := fmt.Sprintf("cold-%d", revision)
		var event *apiv1.WatchEvent
		if revision%2 == 0 {
			event = credentialInvalidation(revision, key)
		} else {
			event = vbucketInvalidation(revision, key, "bucket")
		}
		require.NoError(t, c.processWatch(event))
	}
	for revision := uint64(102); revision < 112; revision++ {
		if revision%2 == 0 {
			require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: revision, Cursor: fmt.Sprintf("cursor-%d", revision), Event: &apiv1.WatchEvent_Credentials{Credentials: &apiv1.CredentialsDelta{AccessKeyId: fmt.Sprintf("removed-%d", revision), Remove: true, NegativeTtl: durationpb.New(time.Minute)}}}))
		} else {
			require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: revision, Cursor: fmt.Sprintf("cursor-%d", revision), Event: &apiv1.WatchEvent_Vbucket{Vbucket: &apiv1.VBucketDelta{AccessKeyId: "owner", BucketName: fmt.Sprintf("removed-%d", revision), Remove: true, NegativeTtl: durationpb.New(time.Minute)}}}))
		}
	}
	require.Zero(t, c.caches.credentials.Len())
	require.Zero(t, c.caches.vbuckets.Len())
}

func TestCredentialLoaderResultDoesNotExposeCacheOwnership(t *testing.T) {
	var calls atomic.Int64
	c := newTestClientWithFake(&fakeControlPlaneClient{lookupCredentials: func(context.Context, *apiv1.LookupCredentialsRequest, ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
		calls.Add(1)
		return &apiv1.LookupCredentialsResponse{SecretKey: "original", IamPolicyJson: controlPlaneAllowAllPolicyJSON, Ttl: durationpb.New(time.Minute), Found: true, Revision: 1}, nil
	}})
	first, err := c.LookupCredentials(context.Background(), "key")
	require.NoError(t, err)
	first.SecretKey = "poison"
	second, err := c.LookupCredentials(context.Background(), "key")
	require.NoError(t, err)
	require.Equal(t, "original", second.SecretKey)
	require.Equal(t, int64(1), calls.Load())
}

func TestNegativeTTLsExpireAndReloadWithInjectedClock(t *testing.T) {
	now := time.Now()
	var credentialCalls, vbucketCalls atomic.Int64
	c := newTestClientWithFake(&fakeControlPlaneClient{
		lookupCredentials: func(context.Context, *apiv1.LookupCredentialsRequest, ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
			credentialCalls.Add(1)
			return &apiv1.LookupCredentialsResponse{Revision: 1, NegativeTtl: durationpb.New(time.Minute)}, nil
		},
		lookupVBucket: func(context.Context, *apiv1.LookupVBucketRequest, ...grpc.CallOption) (*apiv1.LookupVBucketResponse, error) {
			vbucketCalls.Add(1)
			return &apiv1.LookupVBucketResponse{Revision: 1, NegativeTtl: durationpb.New(time.Minute)}, nil
		},
	})
	c.now = func() time.Time { return now }
	c.credentialAdmission = newMissAdmission(c.opts.CredentialMissRate, c.opts.CredentialMissBurst, c.opts.CredentialMissInFlight, now)
	c.vbucketAdmission = newMissAdmission(c.opts.VBucketMissRate, c.opts.VBucketMissBurst, c.opts.VBucketMissInFlight, now)
	for range 2 {
		_, err := c.LookupCredentials(context.Background(), "missing")
		require.ErrorIs(t, err, ErrNotFound)
		_, err = c.LookupVBucket(context.Background(), "owner", "missing")
		require.ErrorIs(t, err, ErrNotFound)
	}
	require.Equal(t, int64(1), credentialCalls.Load())
	require.Equal(t, int64(1), vbucketCalls.Load())
	now = now.Add(time.Minute)
	_, _ = c.LookupCredentials(context.Background(), "missing")
	_, _ = c.LookupVBucket(context.Background(), "owner", "missing")
	require.Equal(t, int64(2), credentialCalls.Load())
	require.Equal(t, int64(2), vbucketCalls.Load())
}

func TestLookupResponseFoundAndNegativeFieldsAreExclusive(t *testing.T) {
	for name, parse := range map[string]func() error{
		"credential found with negative": func() error {
			_, err := credentialResponseEntry(&apiv1.LookupCredentialsResponse{Found: true, Revision: 1, NegativeTtl: durationpb.New(time.Minute)})
			return err
		},
		"credential missing with positive": func() error {
			_, err := credentialResponseEntry(&apiv1.LookupCredentialsResponse{Revision: 1, SecretKey: "secret", NegativeTtl: durationpb.New(time.Minute)})
			return err
		},
		"vbucket found with negative": func() error {
			_, err := vbucketResponseEntry(&apiv1.LookupVBucketResponse{Found: true, Revision: 1, NegativeTtl: durationpb.New(time.Minute)})
			return err
		},
		"vbucket missing with positive": func() error {
			_, err := vbucketResponseEntry(&apiv1.LookupVBucketResponse{Revision: 1, RealBucket: "bucket", NegativeTtl: durationpb.New(time.Minute)})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) { require.Error(t, parse()) })
	}
}

func TestSeparateMissAdmissionBoundsRandomCredentialAndVBucketLoad(t *testing.T) {
	options := defaultClientOptions()
	options.CredentialMissRate, options.CredentialMissBurst, options.CredentialMissInFlight = 0.001, 4, 4
	options.VBucketMissRate, options.VBucketMissBurst, options.VBucketMissInFlight = 0.001, 3, 3
	release := make(chan struct{})
	var credentialCalls, vbucketCalls atomic.Int64
	fake := &fakeControlPlaneClient{
		lookupCredentials: func(context.Context, *apiv1.LookupCredentialsRequest, ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
			credentialCalls.Add(1)
			<-release
			return &apiv1.LookupCredentialsResponse{Revision: 1, NegativeTtl: durationpb.New(time.Minute)}, nil
		},
		lookupVBucket: func(context.Context, *apiv1.LookupVBucketRequest, ...grpc.CallOption) (*apiv1.LookupVBucketResponse, error) {
			vbucketCalls.Add(1)
			<-release
			return &apiv1.LookupVBucketResponse{Revision: 1, NegativeTtl: durationpb.New(time.Minute)}, nil
		},
	}
	c := NewClientWithOptions("test", zerolog.Nop(), options)
	c.client, c.state, c.revision, c.cursor, c.barrierRequired = fake, StateReady, 1, "cursor-1", false
	var wait sync.WaitGroup
	for index := range 50 {
		wait.Add(2)
		go func(i int) {
			defer wait.Done()
			_, _ = c.LookupCredentials(context.Background(), fmt.Sprintf("key-%d", i))
		}(index)
		go func(i int) {
			defer wait.Done()
			_, _ = c.LookupVBucket(context.Background(), "owner", fmt.Sprintf("bucket-%d", i))
		}(index)
	}
	require.Eventually(t, func() bool { return credentialCalls.Load() == 4 && vbucketCalls.Load() == 3 }, time.Second, time.Millisecond)
	close(release)
	wait.Wait()
	require.Equal(t, int64(4), credentialCalls.Load())
	require.Equal(t, int64(3), vbucketCalls.Load())
	require.Equal(t, uint64(46), c.Stats().RejectedCredentialMisses)
	require.Equal(t, uint64(47), c.Stats().RejectedVBucketMisses)
}

func TestEveryUnaryRPCReceivesProxyOwnedDeadline(t *testing.T) {
	validateDeadline := func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			return errors.New("deadline is missing")
		}
		remaining := time.Until(deadline)
		if remaining <= 0 || remaining > 50*time.Millisecond {
			return fmt.Errorf("invalid remaining deadline %s", remaining)
		}
		return nil
	}
	sentinel := status.Error(codes.Unavailable, "stop")
	fake := &fakeControlPlaneClient{
		lookupCredentials: func(ctx context.Context, _ *apiv1.LookupCredentialsRequest, _ ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
			if err := validateDeadline(ctx); err != nil {
				return nil, err
			}
			return nil, sentinel
		},
		lookupVBucket: func(ctx context.Context, _ *apiv1.LookupVBucketRequest, _ ...grpc.CallOption) (*apiv1.LookupVBucketResponse, error) {
			if err := validateDeadline(ctx); err != nil {
				return nil, err
			}
			return nil, sentinel
		},
		createVBucket: func(ctx context.Context, _ *apiv1.CreateVBucketRequest, _ ...grpc.CallOption) (*apiv1.CreateVBucketResponse, error) {
			if err := validateDeadline(ctx); err != nil {
				return nil, err
			}
			return nil, sentinel
		},
		listVBuckets: func(ctx context.Context, _ *apiv1.ListVBucketsRequest, _ ...grpc.CallOption) (*apiv1.ListVBucketsResponse, error) {
			if err := validateDeadline(ctx); err != nil {
				return nil, err
			}
			return nil, sentinel
		},
	}
	options := defaultClientOptions()
	options.UnaryTimeout = 50 * time.Millisecond
	c := NewClientWithOptions("test", zerolog.Nop(), options)
	c.client, c.state, c.revision, c.cursor, c.barrierRequired = fake, StateReady, 1, "cursor-1", false
	_, err := c.LookupCredentials(context.Background(), "key")
	require.Equal(t, codes.Unavailable, status.Code(err))
	_, err = c.LookupVBucket(context.Background(), "key", "bucket")
	require.Equal(t, codes.Unavailable, status.Code(err))
	err = c.CreateVBucket(context.Background(), "key", "bucket", "")
	require.Equal(t, codes.Unavailable, status.Code(err))
	_, err = c.ListVBuckets(context.Background(), "key")
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.Equal(t, uint64(4), c.Stats().RPCCalls)
}

func TestCoalescedLoadSurvivesLeaderCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	c := newTestClientWithFake(&fakeControlPlaneClient{lookupCredentials: func(context.Context, *apiv1.LookupCredentialsRequest, ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
		calls.Add(1)
		close(started)
		<-release
		return &apiv1.LookupCredentialsResponse{SecretKey: "secret", IamPolicyJson: controlPlaneAllowAllPolicyJSON, Ttl: durationpb.New(time.Minute), Found: true, Revision: 1}, nil
	}})
	leaderCtx, cancel := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() { _, err := c.LookupCredentials(leaderCtx, "key"); leaderErr <- err }()
	<-started
	waiter := make(chan *http_server.VirtualCredentials, 1)
	go func() { creds, _ := c.LookupCredentials(context.Background(), "key"); waiter <- creds }()
	require.Eventually(t, func() bool {
		c.credentialLoads.mu.Lock()
		defer c.credentialLoads.mu.Unlock()
		call := c.credentialLoads.calls["key"]
		return call != nil && call.waiters == 1
	}, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-leaderErr, context.Canceled)
	close(release)
	require.Equal(t, "secret", (<-waiter).SecretKey)
	require.Equal(t, int64(1), calls.Load())
}

func TestLocalCacheTTLAndCapacityUseInjectedClock(t *testing.T) {
	now := time.Unix(100, 0)
	cache := newLocalCache[string, cachedCredentials](2, nil, func() time.Time { return now })
	entry := cachedCredentials{Found: false, Revision: 1, TTL: time.Minute}
	cache.Set("a", entry, time.Minute)
	cache.Set("b", entry, time.Minute)
	cache.Set("c", entry, time.Minute)
	require.Equal(t, 2, cache.Len())
	_, found := cache.GetIfPresent("a")
	require.False(t, found, "LRU capacity eviction is O(1) and bounded")
	now = now.Add(time.Minute)
	_, found = cache.GetIfPresent("b")
	require.False(t, found)
}

func TestLoadGroupsDrainAndAdmissionRefillsDeterministically(t *testing.T) {
	var publicationGroup loadGroup[string, int]
	published := make(chan struct{})
	releasePublication := make(chan struct{})
	publicationGroup.afterCompletionPublished = func() {
		close(published)
		<-releasePublication
	}
	value, err, shared := publicationGroup.Do(context.Background(), "key", nil, func() (int, error) { return 1, nil })
	require.NoError(t, err)
	require.False(t, shared)
	require.Equal(t, 1, value)
	<-published
	publicationGroup.mu.Lock()
	require.Empty(t, publicationGroup.calls, "a published completion must no longer be joinable")
	publicationGroup.mu.Unlock()
	close(releasePublication)

	var group loadGroup[string, int]
	value, err, shared = group.Do(context.Background(), "key", nil, func() (int, error) { return 1, nil })
	require.NoError(t, err)
	require.False(t, shared)
	require.Equal(t, 1, value)
	group.mu.Lock()
	require.Empty(t, group.calls)
	group.mu.Unlock()
	var attempts int
	_, err, _ = group.Do(context.Background(), "retry", nil, func() (int, error) {
		attempts++
		return 0, ErrRevisionRace
	})
	require.ErrorIs(t, err, ErrRevisionRace)
	value, err, shared = group.Do(context.Background(), "retry", nil, func() (int, error) {
		attempts++
		return 2, nil
	})
	require.NoError(t, err)
	require.False(t, shared)
	require.Equal(t, 2, value)
	require.Equal(t, 2, attempts)
	now := time.Unix(100, 0)
	admission := newMissAdmission(2, 1, 1, now)
	require.True(t, admission.acquire(now))
	admission.release()
	require.False(t, admission.acquire(now))
	require.True(t, admission.acquire(now.Add(500*time.Millisecond)))
	admission.release()
}

type silentWatchServer struct {
	apiv1.UnimplementedControlPlaneServer
}

type cancellationObservedWatchServer struct {
	apiv1.UnimplementedControlPlaneServer
	canceled chan struct{}
}

func (s cancellationObservedWatchServer) WatchState(_ *apiv1.WatchStateRequest, stream apiv1.ControlPlane_WatchStateServer) error {
	if err := stream.Send(&apiv1.WatchEvent{Revision: 1, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}); err != nil {
		return err
	}
	if err := stream.Send(barrier(1)); err != nil {
		return err
	}
	<-stream.Context().Done()
	close(s.canceled)
	return stream.Context().Err()
}

type closingWatchServer struct {
	apiv1.UnimplementedControlPlaneServer
	failure error
}

type delayedWatchServer struct {
	apiv1.UnimplementedControlPlaneServer
}

func (delayedWatchServer) WatchState(_ *apiv1.WatchStateRequest, stream apiv1.ControlPlane_WatchStateServer) error {
	timer := time.NewTimer(20 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-stream.Context().Done():
		return stream.Context().Err()
	case <-timer.C:
	}
	if err := stream.Send(&apiv1.WatchEvent{Revision: 1, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}); err != nil {
		return err
	}
	if err := stream.Send(barrier(1)); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func (s closingWatchServer) WatchState(_ *apiv1.WatchStateRequest, stream apiv1.ControlPlane_WatchStateServer) error {
	if err := stream.Send(&apiv1.WatchEvent{Revision: 1, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}); err != nil {
		return err
	}
	if err := stream.Send(barrier(1)); err != nil {
		return err
	}
	return s.failure
}

type heartbeatCatchupServer struct {
	apiv1.UnimplementedControlPlaneServer
}

func (heartbeatCatchupServer) CreateVBucket(context.Context, *apiv1.CreateVBucketRequest) (*apiv1.CreateVBucketResponse, error) {
	return &apiv1.CreateVBucketResponse{Revision: 2}, nil
}

func (heartbeatCatchupServer) WatchState(_ *apiv1.WatchStateRequest, stream apiv1.ControlPlane_WatchStateServer) error {
	if err := stream.Send(&apiv1.WatchEvent{Revision: 1, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}); err != nil {
		return err
	}
	if err := stream.Send(barrier(1)); err != nil {
		return err
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ticker.C:
			if err := stream.Send(&apiv1.WatchEvent{Revision: 1, Cursor: "cursor-1", Event: &apiv1.WatchEvent_Heartbeat{Heartbeat: &apiv1.Heartbeat{}}}); err != nil {
				return err
			}
		}
	}
}

type trickleSnapshotServer struct {
	apiv1.UnimplementedControlPlaneServer
}

func (trickleSnapshotServer) WatchState(_ *apiv1.WatchStateRequest, stream apiv1.ControlPlane_WatchStateServer) error {
	if err := stream.Send(&apiv1.WatchEvent{Revision: 1, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}); err != nil {
		return err
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for index := 0; ; index++ {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ticker.C:
			domain := fmt.Sprintf("s3-%d.example.com", index)
			if err := stream.Send(&apiv1.WatchEvent{Revision: 1, Event: &apiv1.WatchEvent_BaseHost{BaseHost: &apiv1.BaseHostDelta{BaseHost: domain}}}); err != nil {
				return err
			}
		}
	}
}

func runControlPlaneServer(t *testing.T, implementation apiv1.ControlPlaneServer) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	apiv1.RegisterControlPlaneServer(server, implementation)
	go server.Serve(listener)
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	return listener.Addr().String()
}

func (silentWatchServer) WatchState(_ *apiv1.WatchStateRequest, stream apiv1.ControlPlane_WatchStateServer) error {
	if err := stream.Send(&apiv1.WatchEvent{Revision: 1, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}); err != nil {
		return err
	}
	if err := stream.Send(barrier(1)); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func TestWatchSilenceFailsReadinessBeforeReconnect(t *testing.T) {
	address := runControlPlaneServer(t, silentWatchServer{})
	options := defaultClientOptions()
	options.WatchSilenceTimeout = 40 * time.Millisecond
	options.ReconnectMinBackoff = time.Second
	options.ReconnectMaxBackoff = time.Second
	c := NewClientWithOptions(address, zerolog.Nop(), options)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	require.Eventually(t, c.Ready, time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return c.Status().State == StateDisconnected }, time.Second, time.Millisecond)
	require.False(t, c.Ready())
	_, lookupErr := c.LookupCredentials(context.Background(), "key")
	require.ErrorIs(t, lookupErr, ErrUnsynchronized)
}

func TestReplacementWatchDiscardsPriorStreamResyncSignal(t *testing.T) {
	address := runControlPlaneServer(t, delayedWatchServer{})
	options := defaultClientOptions()
	options.WatchSilenceTimeout = time.Second
	options.ReconnectMinBackoff = time.Second
	options.ReconnectMaxBackoff = time.Second
	c := NewClientWithOptions(address, zerolog.Nop(), options)
	c.randFloat = func() float64 { return 1 }
	c.resync <- struct{}{} // signal left behind by the retired prior stream
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	require.Eventually(t, c.Ready, 300*time.Millisecond, time.Millisecond)
}

func TestWatchEOFImmediatelyTearsDownReadiness(t *testing.T) {
	address := runControlPlaneServer(t, closingWatchServer{})
	options := defaultClientOptions()
	options.ReconnectMinBackoff = time.Second
	options.ReconnectMaxBackoff = time.Second
	c := NewClientWithOptions(address, zerolog.Nop(), options)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	require.Eventually(t, func() bool {
		status := c.Status()
		return status.State == StateDisconnected && status.LastDisconnectReason == "watch_closed"
	}, time.Second, time.Millisecond)
	require.False(t, c.Ready())
	_, err := c.LookupCredentials(context.Background(), "key")
	require.ErrorIs(t, err, ErrUnsynchronized)
}

func TestWatchTeardownFailsReadinessBeforeClearingTransport(t *testing.T) {
	serverCancellation := make(chan struct{})
	address := runControlPlaneServer(t, cancellationObservedWatchServer{canceled: serverCancellation})
	options := defaultClientOptions()
	options.WatchSilenceTimeout = 40 * time.Millisecond
	options.ReconnectMinBackoff = time.Second
	options.ReconnectMaxBackoff = time.Second
	c := NewClientWithOptions(address, zerolog.Nop(), options)
	disconnected := make(chan struct{})
	releaseCleanup := make(chan struct{})
	var once sync.Once
	c.afterDisconnectState = func() {
		once.Do(func() { close(disconnected) })
		<-releaseCleanup
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	require.Eventually(t, c.Ready, time.Second, time.Millisecond)
	<-disconnected
	status := c.Status()
	require.Equal(t, StateDisconnected, status.State)
	require.False(t, status.Ready)
	require.NotNil(t, c.getClient(), "transport cleanup must follow fail-closed state transition")
	select {
	case <-serverCancellation:
		t.Fatal("watch transport was canceled before readiness failed")
	default:
	}
	close(releaseCleanup)
	require.Eventually(t, func() bool {
		select {
		case <-serverCancellation:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)
}

func TestWatchTransportErrorsDoNotExposeServerTextInLogs(t *testing.T) {
	const sentinel = "AKIA-WATCH-SENTINEL secret-bucket"
	address := runControlPlaneServer(t, closingWatchServer{failure: status.Error(codes.Internal, sentinel)})
	options := defaultClientOptions()
	options.ReconnectMinBackoff = time.Second
	options.ReconnectMaxBackoff = time.Second
	var output lockedBuffer
	c := NewClientWithOptions(address, zerolog.New(&output), options)
	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx)
	require.Eventually(t, func() bool { return c.Status().LastDisconnectReason == "watch_protocol_or_transport_error" }, time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return strings.Contains(output.String(), "watch_protocol_or_transport_error") }, time.Second, time.Millisecond)
	cancel()
	require.Eventually(t, func() bool { return c.Status().State == StateShutdown }, time.Second, time.Millisecond)
	require.NotContains(t, output.String(), sentinel)
}

func TestAbsoluteSynchronizationTimeoutIsNotExtendedByFrames(t *testing.T) {
	for name, implementation := range map[string]apiv1.ControlPlaneServer{
		"startup snapshot trickle":  trickleSnapshotServer{},
		"create catchup heartbeats": heartbeatCatchupServer{},
	} {
		t.Run(name, func(t *testing.T) {
			address := runControlPlaneServer(t, implementation)
			options := defaultClientOptions()
			options.WatchSilenceTimeout = time.Second
			options.SynchronizationTimeout = 40 * time.Millisecond
			options.ReconnectMinBackoff = time.Second
			options.ReconnectMaxBackoff = time.Second
			c := NewClientWithOptions(address, zerolog.Nop(), options)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go c.Run(ctx)
			if name == "create catchup heartbeats" {
				require.Eventually(t, c.Ready, time.Second, time.Millisecond)
				require.NoError(t, c.CreateVBucket(context.Background(), "key", "bucket", ""))
			}
			require.Eventually(t, func() bool { return c.Status().LastDisconnectReason == "synchronization_timeout" }, time.Second, time.Millisecond)
			require.False(t, c.Ready())
		})
	}
}

func TestConcurrentCreateResponsesKeepMaximumTargetAndTerminalState(t *testing.T) {
	started := make(chan string, 2)
	releaseHigh, releaseLow := make(chan struct{}), make(chan struct{})
	c := newTestClientWithFake(&fakeControlPlaneClient{createVBucket: func(_ context.Context, req *apiv1.CreateVBucketRequest, _ ...grpc.CallOption) (*apiv1.CreateVBucketResponse, error) {
		started <- req.BucketName
		if req.BucketName == "high" {
			<-releaseHigh
			return &apiv1.CreateVBucketResponse{Revision: 9}, nil
		}
		<-releaseLow
		return &apiv1.CreateVBucketResponse{Revision: 7}, nil
	}})
	errs := make(chan error, 2)
	go func() { errs <- c.CreateVBucket(context.Background(), "key", "high", "") }()
	go func() { errs <- c.CreateVBucket(context.Background(), "key", "low", "") }()
	<-started
	<-started
	close(releaseHigh)
	require.NoError(t, <-errs)
	close(releaseLow)
	require.NoError(t, <-errs)
	require.Equal(t, uint64(9), c.Status().RequiredRevision)
	require.Equal(t, StateSynchronizing, c.Status().State)

	lateStarted, lateRelease := make(chan struct{}), make(chan struct{})
	c.client = &fakeControlPlaneClient{lookupCredentials: func(context.Context, *apiv1.LookupCredentialsRequest, ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
		close(lateStarted)
		<-lateRelease
		return &apiv1.LookupCredentialsResponse{Revision: 12, Found: true, IamPolicyJson: "invalid"}, nil
	}}
	c.syncMu.Lock()
	c.state, c.revision, c.cursor, c.barrierRequired = StateReady, 9, "cursor-9", false
	c.requiredRevision = 0
	c.syncMu.Unlock()
	lateErr := make(chan error, 1)
	go func() { _, err := c.LookupCredentials(context.Background(), "key"); lateErr <- err }()
	<-lateStarted
	c.markUnsynchronized(StateShutdown)
	close(lateRelease)
	require.Error(t, <-lateErr)
	require.Equal(t, StateShutdown, c.Status().State)
	require.Zero(t, c.Status().RequiredRevision)
}

func TestMalformedCreateResponseFailsClosed(t *testing.T) {
	c := newTestClientWithFake(&fakeControlPlaneClient{createVBucket: func(context.Context, *apiv1.CreateVBucketRequest, ...grpc.CallOption) (*apiv1.CreateVBucketResponse, error) {
		return &apiv1.CreateVBucketResponse{Revision: 1}, nil
	}})
	require.ErrorIs(t, c.CreateVBucket(context.Background(), "key", "bucket", ""), ErrRevisionRace)
	require.False(t, c.Ready())
}

func TestCreateResponseValidationSurvivesConcurrentShutdown(t *testing.T) {
	for name, revision := range map[string]uint64{
		"valid committed response": 2,
		"malformed response":       1,
	} {
		t.Run(name, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			c := newTestClientWithFake(&fakeControlPlaneClient{createVBucket: func(context.Context, *apiv1.CreateVBucketRequest, ...grpc.CallOption) (*apiv1.CreateVBucketResponse, error) {
				close(started)
				<-release
				return &apiv1.CreateVBucketResponse{Revision: revision}, nil
			}})
			result := make(chan error, 1)
			go func() { result <- c.CreateVBucket(context.Background(), "key", "bucket", "") }()
			<-started
			c.markUnsynchronized(StateShutdown)
			close(release)
			err := <-result
			if revision == 2 {
				require.NoError(t, err, "a confirmed mutation must not become ambiguous when the watch shuts down")
			} else {
				require.ErrorIs(t, err, ErrRevisionRace)
			}
			require.Equal(t, StateShutdown, c.Status().State)
		})
	}
}

func TestCommittedCreateRecordsTargetAcrossConcurrentDisconnect(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	c := newTestClientWithFake(&fakeControlPlaneClient{createVBucket: func(context.Context, *apiv1.CreateVBucketRequest, ...grpc.CallOption) (*apiv1.CreateVBucketResponse, error) {
		close(started)
		<-release
		return &apiv1.CreateVBucketResponse{Revision: 2}, nil
	}})
	result := make(chan error, 1)
	go func() { result <- c.CreateVBucket(context.Background(), "key", "bucket", "") }()
	<-started
	c.markUnsynchronized(StateDisconnected)
	close(release)
	require.NoError(t, <-result)
	status := c.Status()
	require.Equal(t, StateDisconnected, status.State)
	require.Equal(t, uint64(2), status.RequiredRevision)

	c.syncMu.Lock()
	c.transitionLocked(StateSynchronizing)
	c.syncMu.Unlock()
	require.NoError(t, c.processWatch(barrier(1)))
	status = c.Status()
	require.Equal(t, StateSynchronizing, status.State)
	require.Equal(t, uint64(2), status.RequiredRevision)
	require.False(t, status.Ready)
}

func TestWatchDescriptorsContainNoCredentialOrBackendSecrets(t *testing.T) {
	require.Nil(t, (&apiv1.CredentialsDelta{}).ProtoReflect().Descriptor().Fields().ByName("secret_key"))
	require.Nil(t, (&apiv1.CredentialsDelta{}).ProtoReflect().Descriptor().Fields().ByName("iam_policy_json"))
	require.Nil(t, (&apiv1.VBucketDelta{}).ProtoReflect().Descriptor().Fields().ByName("real_secret_key"))
	require.Nil(t, (&apiv1.VBucketDelta{}).ProtoReflect().Descriptor().Fields().ByName("real_endpoint"))
	baseFields := (&apiv1.BaseHostDelta{}).ProtoReflect().Descriptor().Fields()
	require.Nil(t, baseFields.ByNumber(1))
	require.Equal(t, int32(3), int32(baseFields.ByName("base_host").Number()))
	assertReserved(t, (&apiv1.BaseHostDelta{}).ProtoReflect().Descriptor(), []protoreflect.FieldNumber{1, 4, 5}, []protoreflect.Name{"hostname", "found", "ttl"})
	assertReserved(t, (&apiv1.CredentialsDelta{}).ProtoReflect().Descriptor(), []protoreflect.FieldNumber{3, 4, 5}, []protoreflect.Name{"secret_key", "iam_policy_json", "ttl"})
	assertReserved(t, (&apiv1.VBucketDelta{}).ProtoReflect().Descriptor(), []protoreflect.FieldNumber{4, 5, 6, 7, 8, 9, 10, 11, 12}, []protoreflect.Name{"real_endpoint", "real_bucket", "real_access_key", "real_secret_key", "real_region", "path_prefix", "real_use_path_style", "ttl", "routing_token_key"})
	assertReserved(t, (&apiv1.CreateVBucketResponse{}).ProtoReflect().Descriptor(), []protoreflect.FieldNumber{1, 2, 3, 4, 5, 6, 7, 8, 9}, []protoreflect.Name{"real_endpoint", "real_bucket", "real_access_key", "real_secret_key", "real_region", "path_prefix", "real_use_path_style", "ttl", "routing_token_key"})
}

func assertReserved(t *testing.T, descriptor protoreflect.MessageDescriptor, numbers []protoreflect.FieldNumber, names []protoreflect.Name) {
	t.Helper()
	for _, number := range numbers {
		found := false
		for index := 0; index < descriptor.ReservedRanges().Len(); index++ {
			bounds := descriptor.ReservedRanges().Get(index)
			if number >= bounds[0] && number < bounds[1] {
				found = true
				break
			}
		}
		require.Truef(t, found, "field number %d is not reserved", number)
	}
	for _, name := range names {
		found := false
		for index := 0; index < descriptor.ReservedNames().Len(); index++ {
			if descriptor.ReservedNames().Get(index) == name {
				found = true
				break
			}
		}
		require.Truef(t, found, "field name %s is not reserved", name)
	}
}

func TestBaseDomainValidationAndLabelBoundaries(t *testing.T) {
	for _, invalid := range []string{"com", "bad_domain.example.com", "-bad.example.com", strings.Repeat("a", 254)} {
		_, err := normalizeBaseDomain(invalid)
		require.Error(t, err)
	}
	c := readyTestClient(1)
	c.baseHosts = map[string]uint64{"example.com": 1, "s3.example.com": 1}
	base, found, err := c.LookupBaseHost(context.Background(), "bucket.s3.example.com")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "s3.example.com", base)
	_, found, err = c.LookupBaseHost(context.Background(), "evilnotexample.com")
	require.NoError(t, err)
	require.False(t, found)
	_, found, err = c.LookupBaseHost(context.Background(), "::1")
	require.NoError(t, err)
	require.False(t, found)
}

func TestMalformedInvalidationShapesFailClosed(t *testing.T) {
	for name, event := range map[string]*apiv1.WatchEvent{
		"credential update negative ttl": {Revision: 2, Cursor: "cursor-2", Event: &apiv1.WatchEvent_Credentials{Credentials: &apiv1.CredentialsDelta{AccessKeyId: "key", NegativeTtl: durationpb.New(time.Minute)}}},
		"credential removal no ttl":      {Revision: 2, Cursor: "cursor-2", Event: &apiv1.WatchEvent_Credentials{Credentials: &apiv1.CredentialsDelta{AccessKeyId: "key", Remove: true}}},
		"vbucket update negative ttl":    {Revision: 2, Cursor: "cursor-2", Event: &apiv1.WatchEvent_Vbucket{Vbucket: &apiv1.VBucketDelta{AccessKeyId: "key", BucketName: "bucket", NegativeTtl: durationpb.New(time.Minute)}}},
	} {
		t.Run(name, func(t *testing.T) {
			c := readyTestClient(1)
			require.Error(t, c.processWatch(event))
			require.False(t, c.Ready())
		})
	}
}

var _ = errors.Is
