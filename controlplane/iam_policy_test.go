package controlplane

import (
	"context"
	"errors"
	"fmt"
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
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const controlPlaneAllowAllPolicyJSON = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`

var controlPlaneRoutingTokenKey = []byte("0123456789abcdef0123456789abcdef")

type fakeControlPlaneClient struct {
	lookupCredentials func(ctx context.Context, in *apiv1.LookupCredentialsRequest, opts ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error)
	lookupVBucket     func(ctx context.Context, in *apiv1.LookupVBucketRequest, opts ...grpc.CallOption) (*apiv1.LookupVBucketResponse, error)
	createVBucket     func(ctx context.Context, in *apiv1.CreateVBucketRequest, opts ...grpc.CallOption) (*apiv1.CreateVBucketResponse, error)
	listVBuckets      func(ctx context.Context, in *apiv1.ListVBucketsRequest, opts ...grpc.CallOption) (*apiv1.ListVBucketsResponse, error)
}

func (f *fakeControlPlaneClient) LookupCredentials(ctx context.Context, in *apiv1.LookupCredentialsRequest, opts ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
	if f.lookupCredentials == nil {
		return nil, errors.New("not implemented")
	}
	return f.lookupCredentials(ctx, in, opts...)
}

func (f *fakeControlPlaneClient) LookupVBucket(ctx context.Context, in *apiv1.LookupVBucketRequest, opts ...grpc.CallOption) (*apiv1.LookupVBucketResponse, error) {
	if f.lookupVBucket == nil {
		return nil, errors.New("not implemented")
	}
	return f.lookupVBucket(ctx, in, opts...)
}

func (f *fakeControlPlaneClient) WatchState(context.Context, *apiv1.WatchStateRequest, ...grpc.CallOption) (apiv1.ControlPlane_WatchStateClient, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeControlPlaneClient) CreateVBucket(ctx context.Context, in *apiv1.CreateVBucketRequest, opts ...grpc.CallOption) (*apiv1.CreateVBucketResponse, error) {
	if f.createVBucket == nil {
		return nil, errors.New("not implemented")
	}
	return f.createVBucket(ctx, in, opts...)
}

func (f *fakeControlPlaneClient) ListVBuckets(ctx context.Context, in *apiv1.ListVBucketsRequest, opts ...grpc.CallOption) (*apiv1.ListVBucketsResponse, error) {
	if f.listVBuckets == nil {
		return nil, errors.New("not implemented")
	}
	return f.listVBuckets(ctx, in, opts...)
}

func newTestClientWithFake(fake apiv1.ControlPlaneClient) *Client {
	c := NewClient("test-control-plane", zerolog.Nop())
	c.client = fake
	c.state = StateReady
	c.revision = 1
	c.cursor = "cursor-1"
	c.barrierRequired = false
	return c
}

func TestLookupCredentials_ParsesIAMPolicyBeforeCaching(t *testing.T) {
	c := newTestClientWithFake(&fakeControlPlaneClient{
		lookupCredentials: func(_ context.Context, in *apiv1.LookupCredentialsRequest, _ ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
			require.Equal(t, "access-key", in.AccessKeyId)
			return &apiv1.LookupCredentialsResponse{
				SecretKey:     "secret",
				IamPolicyJson: controlPlaneAllowAllPolicyJSON,
				Ttl:           durationpb.New(time.Minute),
				Found:         true,
				Revision:      1,
			}, nil
		},
	})

	creds, err := c.LookupCredentials(context.Background(), "access-key")
	require.NoError(t, err)
	require.Equal(t, "secret", creds.SecretKey)
	require.NoError(t, creds.IAMPolicy.Authorize(iam.Request{
		Action:   "s3:DeleteObject",
		Resource: "arn:aws:s3:::bucket/key",
	}))
}

func TestLookupCredentials_InvalidIAMPolicyIsNotCached(t *testing.T) {
	var calls atomic.Int64
	c := newTestClientWithFake(&fakeControlPlaneClient{
		lookupCredentials: func(_ context.Context, _ *apiv1.LookupCredentialsRequest, _ ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
			calls.Add(1)
			return &apiv1.LookupCredentialsResponse{
				SecretKey:     "secret",
				IamPolicyJson: `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"s3:ExistingObjectTag/class":"public"}}}}`,
				Ttl:           durationpb.New(time.Minute),
				Found:         true,
				Revision:      1,
			}, nil
		},
	})

	_, err := c.LookupCredentials(context.Background(), "access-key")
	require.ErrorIs(t, err, iam.ErrInvalidPolicy)
	_, err = c.LookupCredentials(context.Background(), "access-key")
	require.ErrorIs(t, err, iam.ErrInvalidPolicy)
	require.Equal(t, int64(2), calls.Load())
}

func invalidTTLTestCases() []struct {
	name string
	ttl  *durationpb.Duration
} {
	return []struct {
		name string
		ttl  *durationpb.Duration
	}{
		{name: "nil", ttl: nil},
		{name: "zero", ttl: durationpb.New(0)},
		{name: "negative", ttl: durationpb.New(-time.Minute)},
	}
}

func TestLookupCaches_InvalidTTLsAreNotCached(t *testing.T) {
	for _, tt := range invalidTTLTestCases() {
		t.Run("credentials/"+tt.name, func(t *testing.T) {
			c := newTestClientWithFake(&fakeControlPlaneClient{
				lookupCredentials: func(_ context.Context, _ *apiv1.LookupCredentialsRequest, _ ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
					return &apiv1.LookupCredentialsResponse{
						SecretKey:     "secret",
						IamPolicyJson: controlPlaneAllowAllPolicyJSON,
						Ttl:           tt.ttl,
						Found:         true,
						Revision:      1,
					}, nil
				},
			})

			_, err := c.LookupCredentials(context.Background(), "access-key")
			require.Error(t, err)
			_, ok := c.caches.credentials.GetIfPresent("access-key")
			require.False(t, ok)
		})

		t.Run("vbucket/"+tt.name, func(t *testing.T) {
			c := newTestClientWithFake(&fakeControlPlaneClient{
				lookupVBucket: func(_ context.Context, _ *apiv1.LookupVBucketRequest, _ ...grpc.CallOption) (*apiv1.LookupVBucketResponse, error) {
					return &apiv1.LookupVBucketResponse{
						RealEndpoint:     "https://s3.example.com",
						RealBucket:       "real-bucket",
						RealAccessKey:    "real-access",
						RealSecretKey:    "real-secret",
						RealRegion:       "us-east-1",
						PathPrefix:       "tenant",
						RealUsePathStyle: true,
						RoutingTokenKey:  controlPlaneRoutingTokenKey,
						Ttl:              tt.ttl,
						Found:            true,
						Revision:         1,
					}, nil
				},
			})

			_, err := c.LookupVBucket(context.Background(), "access-key", "bucket")
			require.Error(t, err)
			_, ok := c.caches.vbuckets.GetIfPresent(vbucketCacheKey("access-key", "bucket"))
			require.False(t, ok)
		})
	}
}

func TestVBucketMappingsAreValidatedBeforeEveryCacheInsertion(t *testing.T) {
	t.Run("lookup does not cache invalid mapping", func(t *testing.T) {
		var calls atomic.Int64
		c := newTestClientWithFake(&fakeControlPlaneClient{
			lookupVBucket: func(_ context.Context, _ *apiv1.LookupVBucketRequest, _ ...grpc.CallOption) (*apiv1.LookupVBucketResponse, error) {
				calls.Add(1)
				return &apiv1.LookupVBucketResponse{
					RealEndpoint: "https://user:secret@s3.example.com/path", RealBucket: "real-bucket",
					RealAccessKey: "real-access", RealSecretKey: "real-secret", RealRegion: "us-east-1",
					PathPrefix: "tenant", RealUsePathStyle: true, RoutingTokenKey: controlPlaneRoutingTokenKey,
					Ttl: durationpb.New(time.Minute), Found: true, Revision: 1,
				}, nil
			},
		})
		for range 2 {
			_, err := c.LookupVBucket(context.Background(), "access-key", "bucket")
			require.Error(t, err)
		}
		require.Equal(t, int64(2), calls.Load())
		_, found := c.caches.vbuckets.GetIfPresent(vbucketCacheKey("access-key", "bucket"))
		require.False(t, found)
	})

}

func TestVBucketCacheDoesNotExposeMutableMappingAliases(t *testing.T) {
	t.Run("lookup result", func(t *testing.T) {
		var calls atomic.Int64
		c := newTestClientWithFake(&fakeControlPlaneClient{lookupVBucket: func(_ context.Context, _ *apiv1.LookupVBucketRequest, _ ...grpc.CallOption) (*apiv1.LookupVBucketResponse, error) {
			calls.Add(1)
			return &apiv1.LookupVBucketResponse{
				RealEndpoint: "https://s3.example.com", RealBucket: "real-bucket", RealAccessKey: "real-access",
				RealSecretKey: "real-secret", RealRegion: "us-east-1", PathPrefix: "tenant",
				RealUsePathStyle: true, RoutingTokenKey: controlPlaneRoutingTokenKey, Ttl: durationpb.New(time.Minute), Found: true, Revision: 1,
			}, nil
		}})
		first, err := c.LookupVBucket(context.Background(), "access-key", "bucket")
		require.NoError(t, err)
		first.RealBucket = "poisoned"
		first.RoutingTokenKey[0] ^= 0xff
		second, err := c.LookupVBucket(context.Background(), "access-key", "bucket")
		require.NoError(t, err)
		require.Equal(t, int64(1), calls.Load())
		require.Equal(t, "real-bucket", second.RealBucket)
		require.Equal(t, controlPlaneRoutingTokenKey, second.RoutingTokenKey)
	})

}

func TestCreateVBucket_SuccessIsCommittedBeforeWatchCatchup(t *testing.T) {
	c := newTestClientWithFake(&fakeControlPlaneClient{createVBucket: func(_ context.Context, in *apiv1.CreateVBucketRequest, _ ...grpc.CallOption) (*apiv1.CreateVBucketResponse, error) {
		require.Equal(t, uint64(1), in.MinimumRevision)
		return &apiv1.CreateVBucketResponse{Revision: 4}, nil
	}})
	require.NoError(t, c.CreateVBucket(context.Background(), "access-key", "new-bucket", "us-west-2"))
	require.False(t, c.Ready())
	require.Equal(t, uint64(4), c.Status().RequiredRevision)
	for revision := uint64(2); revision <= 4; revision++ {
		require.NoError(t, c.processWatch(&apiv1.WatchEvent{Revision: revision, Cursor: fmt.Sprintf("cursor-%d", revision), Event: &apiv1.WatchEvent_Vbucket{Vbucket: &apiv1.VBucketDelta{AccessKeyId: "access-key", BucketName: "new-bucket"}}}))
	}
	require.True(t, c.Ready())
	require.Equal(t, uint64(4), c.Status().Revision)
}

func TestCreateVBucket_MapsControlPlaneErrors(t *testing.T) {
	tests := []struct {
		name string
		code codes.Code
		want error
	}{
		{name: "owned", code: codes.AlreadyExists, want: http_server.ErrVBucketAlreadyOwnedByYou},
		{name: "exists", code: codes.Aborted, want: http_server.ErrVBucketAlreadyExists},
		{name: "invalid", code: codes.InvalidArgument, want: http_server.ErrInvalidVBucketArgument},
		{name: "denied", code: codes.PermissionDenied, want: http_server.ErrVBucketAccessDenied},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClientWithFake(&fakeControlPlaneClient{
				createVBucket: func(_ context.Context, _ *apiv1.CreateVBucketRequest, _ ...grpc.CallOption) (*apiv1.CreateVBucketResponse, error) {
					return nil, status.Error(tt.code, "test error")
				},
			})

			err := c.CreateVBucket(context.Background(), "access-key", "new-bucket", "")
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestListVBuckets_ConvertsSummaries(t *testing.T) {
	created := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	c := newTestClientWithFake(&fakeControlPlaneClient{
		listVBuckets: func(_ context.Context, in *apiv1.ListVBucketsRequest, _ ...grpc.CallOption) (*apiv1.ListVBucketsResponse, error) {
			require.Equal(t, "access-key", in.AccessKeyId)
			return &apiv1.ListVBucketsResponse{
				Revision: 1,
				Buckets: []*apiv1.VBucketSummary{{
					BucketName:   "bucket-a",
					CreationDate: timestamppb.New(created),
				}},
			}, nil
		},
	})

	buckets, err := c.ListVBuckets(context.Background(), "access-key")
	require.NoError(t, err)
	require.Equal(t, []http_server.ListedVBucket{{
		Name:         "bucket-a",
		CreationDate: created,
	}}, buckets)
}

func TestListVBuckets_RejectsMissingOrInvalidCreationDates(t *testing.T) {
	for name, summary := range map[string]*apiv1.VBucketSummary{
		"nil summary":  nil,
		"missing date": {BucketName: "bucket-a"},
		"invalid date": {BucketName: "bucket-a", CreationDate: &timestamppb.Timestamp{Seconds: 253402300800}},
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestClientWithFake(&fakeControlPlaneClient{
				listVBuckets: func(_ context.Context, _ *apiv1.ListVBucketsRequest, _ ...grpc.CallOption) (*apiv1.ListVBucketsResponse, error) {
					return &apiv1.ListVBucketsResponse{Revision: 1, Buckets: []*apiv1.VBucketSummary{summary}}, nil
				},
			})
			buckets, err := c.ListVBuckets(context.Background(), "access-key")
			require.Error(t, err)
			require.Nil(t, buckets)
		})
	}
}
