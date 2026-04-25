package controlplane

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danthegoodman1/vbuckets/http_server"
	"github.com/danthegoodman1/vbuckets/iam"
	apiv1 "github.com/danthegoodman1/vbuckets/v1"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const controlPlaneAllowAllPolicyJSON = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`

type fakeControlPlaneClient struct {
	lookupCredentials func(ctx context.Context, in *apiv1.LookupCredentialsRequest, opts ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error)
	createVBucket     func(ctx context.Context, in *apiv1.CreateVBucketRequest, opts ...grpc.CallOption) (*apiv1.CreateVBucketResponse, error)
	listVBuckets      func(ctx context.Context, in *apiv1.ListVBucketsRequest, opts ...grpc.CallOption) (*apiv1.ListVBucketsResponse, error)
}

func (f *fakeControlPlaneClient) LookupCredentials(ctx context.Context, in *apiv1.LookupCredentialsRequest, opts ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error) {
	return f.lookupCredentials(ctx, in, opts...)
}

func (f *fakeControlPlaneClient) LookupBaseHost(context.Context, *apiv1.LookupBaseHostRequest, ...grpc.CallOption) (*apiv1.LookupBaseHostResponse, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeControlPlaneClient) LookupVBucket(context.Context, *apiv1.LookupVBucketRequest, ...grpc.CallOption) (*apiv1.LookupVBucketResponse, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeControlPlaneClient) ListenForDeltas(context.Context, *apiv1.ListenForDeltasRequest, ...grpc.CallOption) (apiv1.ControlPlane_ListenForDeltasClient, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeControlPlaneClient) CreateVBucket(ctx context.Context, in *apiv1.CreateVBucketRequest, opts ...grpc.CallOption) (*apiv1.CreateVBucketResponse, error) {
	return f.createVBucket(ctx, in, opts...)
}

func (f *fakeControlPlaneClient) ListVBuckets(ctx context.Context, in *apiv1.ListVBucketsRequest, opts ...grpc.CallOption) (*apiv1.ListVBucketsResponse, error) {
	return f.listVBuckets(ctx, in, opts...)
}

func newTestClientWithFake(fake apiv1.ControlPlaneClient) *Client {
	c := NewClient("test-control-plane", zerolog.Nop())
	c.client = fake
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
			}, nil
		},
	})

	_, err := c.LookupCredentials(context.Background(), "access-key")
	require.ErrorIs(t, err, iam.ErrInvalidPolicy)
	_, err = c.LookupCredentials(context.Background(), "access-key")
	require.ErrorIs(t, err, iam.ErrInvalidPolicy)
	require.Equal(t, int64(2), calls.Load())
}

func TestHandleDelta_CredentialsPolicyUpsertAndInvalidation(t *testing.T) {
	c := NewClient("test-control-plane", zerolog.Nop())
	c.handleDelta(&apiv1.Delta{Delta: &apiv1.Delta_Credentials{Credentials: &apiv1.CredentialsDelta{
		AccessKeyId:   "access-key",
		SecretKey:     "secret",
		IamPolicyJson: controlPlaneAllowAllPolicyJSON,
		Ttl:           durationpb.New(time.Minute),
	}}})

	cached, ok := c.caches.credentials.GetIfPresent("access-key")
	require.True(t, ok)
	require.Equal(t, "secret", cached.SecretKey)
	require.NoError(t, cached.IAMPolicy.Authorize(iam.Request{
		Action:   "s3:PutObject",
		Resource: "arn:aws:s3:::bucket/key",
	}))

	c.handleDelta(&apiv1.Delta{Delta: &apiv1.Delta_Credentials{Credentials: &apiv1.CredentialsDelta{
		AccessKeyId:   "access-key",
		SecretKey:     "secret",
		IamPolicyJson: `not-json`,
		Ttl:           durationpb.New(time.Minute),
	}}})

	_, ok = c.caches.credentials.GetIfPresent("access-key")
	require.False(t, ok)
}

func TestCreateVBucket_WarmsCache(t *testing.T) {
	c := newTestClientWithFake(&fakeControlPlaneClient{
		createVBucket: func(_ context.Context, in *apiv1.CreateVBucketRequest, _ ...grpc.CallOption) (*apiv1.CreateVBucketResponse, error) {
			require.Equal(t, "access-key", in.AccessKeyId)
			require.Equal(t, "new-bucket", in.BucketName)
			require.Equal(t, "us-west-2", in.LocationConstraint)
			return &apiv1.CreateVBucketResponse{
				RealEndpoint:     "https://s3.example.com",
				RealBucket:       "real-bucket",
				RealAccessKey:    "real-access",
				RealSecretKey:    "real-secret",
				RealRegion:       "us-east-1",
				PathPrefix:       "tenants/access-key/new-bucket",
				RealUsePathStyle: true,
				Ttl:              durationpb.New(time.Minute),
			}, nil
		},
	})

	cfg, err := c.CreateVBucket(context.Background(), "access-key", "new-bucket", "us-west-2")
	require.NoError(t, err)
	require.Equal(t, "real-bucket", cfg.RealBucket)

	cached, ok := c.caches.vbuckets.GetIfPresent(vbucketCacheKey("access-key", "new-bucket"))
	require.True(t, ok)
	require.Equal(t, "tenants/access-key/new-bucket", cached.PathPrefix)
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

			_, err := c.CreateVBucket(context.Background(), "access-key", "new-bucket", "")
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
