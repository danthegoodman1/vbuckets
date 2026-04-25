package controlplane

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danthegoodman1/vbuckets/iam"
	apiv1 "github.com/danthegoodman1/vbuckets/v1"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
)

const controlPlaneAllowAllPolicyJSON = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`

type fakeControlPlaneClient struct {
	lookupCredentials func(ctx context.Context, in *apiv1.LookupCredentialsRequest, opts ...grpc.CallOption) (*apiv1.LookupCredentialsResponse, error)
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
