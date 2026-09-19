package controlplane

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	apiv1 "github.com/danthegoodman1/vbuckets/api/v1"
	"github.com/danthegoodman1/vbuckets/http_server"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

type boundaryResolver struct {
	*Client
	afterHost, afterMapping func()
}

func (r boundaryResolver) LookupBaseHost(ctx context.Context, host string) (string, bool, error) {
	base, found, err := r.Client.LookupBaseHost(ctx, host)
	if r.afterHost != nil {
		r.afterHost()
	}
	return base, found, err
}
func (r boundaryResolver) LookupVBucket(ctx context.Context, key, bucket string) (*http_server.VBucketConfig, error) {
	value, err := r.Client.LookupVBucket(ctx, key, bucket)
	if r.afterMapping != nil {
		r.afterMapping()
	}
	return value, err
}

type boundaryBody struct {
	io.Reader
	once   sync.Once
	change func()
}

func (b *boundaryBody) Read(p []byte) (int, error) { b.once.Do(b.change); return b.Reader.Read(p) }
func (b *boundaryBody) Close() error               { return nil }

func TestRequestCannotAuthorizeAcrossControlPlaneChanges(t *testing.T) {
	for _, change := range []string{"remove", "rotate", "mapping", "disconnect"} {
		for _, operation := range []string{"get", "list", "create-body", "complete-body"} {
			t.Run(change+"/"+operation, func(t *testing.T) {
				c := newTestClientWithFake(&fakeControlPlaneClient{lookupVBucket: func(_ context.Context, req *apiv1.LookupVBucketRequest, _ ...grpc.CallOption) (*apiv1.LookupVBucketResponse, error) {
					return &apiv1.LookupVBucketResponse{RealEndpoint: "https://origin.example.com", RealBucket: "real-bucket", RealAccessKey: "real-key", RealSecretKey: "real-secret", RealRegion: "us-east-1", RoutingTokenKey: controlPlaneRoutingTokenKey, Found: true, Revision: req.MinimumRevision, Ttl: durationpb.New(time.Minute)}, nil
				}})
				policy, err := http_server.ParseS3IAMPolicyJSON(controlPlaneAllowAllPolicyJSON)
				require.NoError(t, err)
				c.caches.credentials.Set("key", cachedCredentials{VirtualCredentials: &http_server.VirtualCredentials{SecretKey: "secret", IAMPolicy: policy}, Found: true, Revision: 1}, time.Minute)
				c.caches.vbuckets.Set(vbucketCacheKey("key", "bucket"), cachedVBucket{VBucketConfig: &http_server.VBucketConfig{}, Found: true, Revision: 1}, time.Minute)
				mutate := func() {
					switch change {
					case "remove":
						event := credentialInvalidation(2, "key")
						event.GetCredentials().Remove = true
						event.GetCredentials().NegativeTtl = durationpb.New(time.Minute)
						require.NoError(t, c.processWatch(event))
					case "rotate":
						require.NoError(t, c.processWatch(credentialInvalidation(2, "key")))
					case "mapping":
						require.NoError(t, c.processWatch(vbucketInvalidation(2, "key", "bucket")))
					case "disconnect":
						c.markUnsynchronized(StateDisconnected)
					}
				}
				resolver := boundaryResolver{Client: c}
				method, path := http.MethodGet, "/bucket/key"
				var body io.Reader
				switch operation {
				case "get":
					resolver.afterMapping = mutate
				case "list":
					path = "/"
					resolver.afterHost = mutate
				case "create-body":
					method, path = http.MethodPut, "/bucket"
					body = &boundaryBody{Reader: strings.NewReader(`<CreateBucketConfiguration><LocationConstraint>us-east-1</LocationConstraint></CreateBucketConfiguration>`), change: mutate}
				case "complete-body":
					method, path = http.MethodPost, "/bucket/key?uploadId=opaque"
					// The stale state must be rejected before opaque token decoding/dispatch.
					body = &boundaryBody{Reader: strings.NewReader(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"etag"</ETag></Part></CompleteMultipartUpload>`), change: mutate}
				}
				req, err := http.NewRequest(method, "http://s3.example.com"+path, body)
				require.NoError(t, err)
				req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
				require.NoError(t, awsv4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: "key", SecretAccessKey: "secret"}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now()))
				dispatched := false
				handler := http_server.S3Auth(resolver)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { dispatched = true }))
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				require.False(t, dispatched)
				require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
			})
		}
	}
}

func TestResolutionStampRetiresWhenSameRevisionReconnects(t *testing.T) {
	c := newTestClientWithFake(&fakeControlPlaneClient{})
	stamp, err := c.BeginResolution()
	require.NoError(t, err)
	c.markUnsynchronized(StateDisconnected)
	c.syncMu.Lock()
	c.transitionLocked(StateSynchronizing)
	c.syncMu.Unlock()
	require.NoError(t, c.processWatch(barrier(1)))
	require.True(t, c.Ready())
	require.ErrorIs(t, c.ValidateResolution(stamp), ErrRevisionRace)
}

type futureUnaryServer struct {
	apiv1.UnimplementedControlPlaneServer
	release chan struct{}
	streams atomic.Int32
}

func (*futureUnaryServer) LookupCredentials(context.Context, *apiv1.LookupCredentialsRequest) (*apiv1.LookupCredentialsResponse, error) {
	return &apiv1.LookupCredentialsResponse{Revision: 2, Found: true, SecretKey: "secret", IamPolicyJson: controlPlaneAllowAllPolicyJSON, Ttl: durationpb.New(time.Minute)}, nil
}
func (s *futureUnaryServer) WatchState(_ *apiv1.WatchStateRequest, stream apiv1.ControlPlane_WatchStateServer) error {
	s.streams.Add(1)
	if err := stream.Send(&apiv1.WatchEvent{Revision: 1, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}); err != nil {
		return err
	}
	if err := stream.Send(barrier(1)); err != nil {
		return err
	}
	revision := uint64(1)
	release := s.release
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-release:
			if err := stream.Send(credentialInvalidation(2, "other")); err != nil {
				return err
			}
			revision, release = 2, nil
		case <-ticker.C:
			if err := stream.Send(&apiv1.WatchEvent{Revision: revision, Cursor: fmt.Sprintf("cursor-%d", revision), Event: &apiv1.WatchEvent_Heartbeat{Heartbeat: &apiv1.Heartbeat{}}}); err != nil {
				return err
			}
		}
	}
}

func TestFutureUnaryCatchesUpOnSameStreamOrTimesOut(t *testing.T) {
	for _, catchUp := range []bool{true, false} {
		t.Run(fmt.Sprint(catchUp), func(t *testing.T) {
			server := &futureUnaryServer{release: make(chan struct{})}
			address := runControlPlaneServer(t, server)
			options := defaultClientOptions()
			options.SynchronizationTimeout = 200 * time.Millisecond
			options.WatchSilenceTimeout = time.Second
			options.ReconnectMinBackoff = time.Second
			options.ReconnectMaxBackoff = time.Second
			c := NewClientWithOptions(address, zerolog.Nop(), options)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go c.Run(ctx)
			require.Eventually(t, c.Ready, time.Second, time.Millisecond)
			_, err := c.LookupCredentials(ctx, "key")
			require.ErrorIs(t, err, ErrRevisionRace)
			require.Equal(t, StateSynchronizing, c.Status().State)
			require.Equal(t, uint64(2), c.Status().RequiredRevision)
			require.Empty(t, c.resync)
			if catchUp {
				close(server.release)
				require.Eventually(t, c.Ready, time.Second, time.Millisecond)
				require.Equal(t, uint64(2), c.Status().Revision)
				value, err := c.LookupCredentials(ctx, "key")
				require.NoError(t, err)
				require.Equal(t, "secret", value.SecretKey)
			} else {
				require.Eventually(t, func() bool { return c.Status().State == StateDisconnected }, time.Second, time.Millisecond)
				require.Equal(t, "synchronization_timeout", c.Status().LastDisconnectReason)
			}
			require.Equal(t, int32(1), server.streams.Load())
		})
	}
}

func TestResolverErrorClassification(t *testing.T) {
	for _, tt := range []struct{ err, target error }{
		{status.Error(codes.NotFound, "private"), http_server.ErrResolverNotFound},
		{status.Error(codes.PermissionDenied, "private"), http_server.ErrVBucketAccessDenied},
		{status.Error(codes.Unavailable, "private"), http_server.ErrResolverUnavailable},
		{status.Error(codes.Internal, "private"), http_server.ErrResolverUnavailable},
		{status.Error(codes.ResourceExhausted, "private"), http_server.ErrResolverThrottled},
		{context.DeadlineExceeded, http_server.ErrResolverUnavailable},
		{fmt.Errorf("invalid payload"), http_server.ErrResolverInvalidResponse},
	} {
		err := mapResolverError(fmt.Errorf("wrapped: %w", tt.err))
		require.ErrorIs(t, err, tt.target)
		require.ErrorIs(t, err, tt.err)
	}
}
