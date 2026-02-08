package controlplane

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestBuildTransportCredentials_DefaultsToInsecure(t *testing.T) {
	_, err := buildTransportCredentials(controlPlaneDialConfig{})
	require.NoError(t, err)
}

func TestBuildTransportCredentials_RejectsUnknownMode(t *testing.T) {
	_, err := buildTransportCredentials(controlPlaneDialConfig{
		SecurityMode: "unknown-mode",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported CONTROL_PLANE_SECURITY_MODE")
}

func TestBuildTransportCredentials_MTLSRequiresCertAndKey(t *testing.T) {
	_, err := buildTransportCredentials(controlPlaneDialConfig{
		SecurityMode: "mtls",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "CONTROL_PLANE_TLS_CERT_FILE")
}

func TestBearerAuthUnaryInterceptor_AddsAuthorizationMetadata(t *testing.T) {
	interceptor := bearerAuthUnaryInterceptor("test-token")

	var called bool
	err := interceptor(context.Background(), "/vbuckets.v1.ControlPlane/LookupCredentials", nil, nil, nil, func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		called = true
		md, ok := metadata.FromOutgoingContext(ctx)
		require.True(t, ok)
		require.Equal(t, []string{"Bearer test-token"}, md.Get("authorization"))
		return nil
	})

	require.NoError(t, err)
	require.True(t, called)
}

func TestBearerAuthStreamInterceptor_AddsAuthorizationMetadata(t *testing.T) {
	interceptor := bearerAuthStreamInterceptor("stream-token")

	var called bool
	_, err := interceptor(context.Background(), &grpc.StreamDesc{}, nil, "/vbuckets.v1.ControlPlane/ListenForDeltas", func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		called = true
		md, ok := metadata.FromOutgoingContext(ctx)
		require.True(t, ok)
		require.Equal(t, []string{"Bearer stream-token"}, md.Get("authorization"))
		return nil, nil
	})

	require.NoError(t, err)
	require.True(t, called)
}
