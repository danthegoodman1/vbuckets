package controlplane

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	apiv1 "github.com/danthegoodman1/vbuckets/api/v1"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
)

// These are the focused regressions that failed against the old unversioned,
// per-request-base-host client before the Phase 3 implementation.

func TestRegressionStaleUnaryCannotWinAgainstNewerWatchEvent(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	c := newTestClientWithFake(&fakeControlPlaneClient{
		lookupCredentials: func(context.Context, *apiv1.LookupCredentialsRequest, ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
			if calls.Add(1) == 1 {
				close(started)
				<-release
				return &apiv1.LookupCredentialsResponse{
					SecretKey: "stale-secret", IamPolicyJson: controlPlaneAllowAllPolicyJSON,
					Ttl: durationpb.New(time.Minute), Found: true, Revision: 1,
				}, nil
			}
			return &apiv1.LookupCredentialsResponse{
				SecretKey: "new-secret", IamPolicyJson: controlPlaneAllowAllPolicyJSON,
				Ttl: durationpb.New(time.Minute), Found: true, Revision: 2,
			}, nil
		},
	})

	result := make(chan string, 1)
	go func() {
		creds, err := c.LookupCredentials(context.Background(), "access-key")
		if err != nil {
			result <- "error: " + err.Error()
			return
		}
		result <- creds.SecretKey
	}()
	<-started
	require.NoError(t, c.processWatch(&apiv1.WatchEvent{
		Revision: 2, Cursor: "cursor-2",
		Event: &apiv1.WatchEvent_Credentials{Credentials: &apiv1.CredentialsDelta{
			AccessKeyId: "access-key",
		}},
	}))
	close(release)
	require.Equal(t, "new-secret", <-result)
	require.Equal(t, int64(2), calls.Load())
}

func TestRegressionCredentialNotFoundIsNegativelyCached(t *testing.T) {
	var calls atomic.Int64
	c := newTestClientWithFake(&fakeControlPlaneClient{
		lookupCredentials: func(context.Context, *apiv1.LookupCredentialsRequest, ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
			calls.Add(1)
			return &apiv1.LookupCredentialsResponse{Found: false, NegativeTtl: durationpb.New(time.Minute), Revision: 1}, nil
		},
	})

	for range 2 {
		_, err := c.LookupCredentials(context.Background(), "random-invalid-key")
		require.ErrorIs(t, err, ErrNotFound)
	}
	require.Equal(t, int64(1), calls.Load(), "a legitimate negative result must suppress repeated control-plane load")
}

func TestRegressionBaseHostsUseLocalLongestSuffixRegistry(t *testing.T) {
	c := NewClient("test-control-plane", zerolog.Nop())
	c.state = StateSynchronizing
	require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 5, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}))
	for _, domain := range []string{"example.com", "s3.example.com"} {
		require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 5, Event: &apiv1.WatchEvent_BaseHost{BaseHost: &apiv1.BaseHostDelta{BaseHost: domain}}}))
	}
	require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: 5, Cursor: "cursor-5", Event: &apiv1.WatchEvent_SynchronizationBarrier{SynchronizationBarrier: &apiv1.SynchronizationBarrier{}}}))

	base, found, err := c.LookupBaseHost(context.Background(), "BUCKET.deep.s3.example.com.")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "s3.example.com", base)
	require.Equal(t, 2, c.Stats().BaseHostEntries, "request hostname cardinality must not create registry entries")
}
