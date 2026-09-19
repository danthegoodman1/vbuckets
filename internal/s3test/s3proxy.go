// Package s3test provides the shared S3 origin for Docker integration tests.
package s3test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// Pin the multi-platform index so both arm64 and amd64 use the same release.
	image     = "andrewgaul/s3proxy:4.0.0@sha256:66045829af4a6ed7ba7541febcb3914b5e7408680735fd325a999bbabf7137f3"
	AccessKey = "e2e-origin-access-key"
	SecretKey = "e2e-origin-secret-key"
	Bucket    = "e2e-bucket"
	Region    = "us-east-1"
)

// Start creates an isolated, SigV4-authenticated origin and physical bucket.
// The container and its filesystem are removed when the test finishes.
func Start(t *testing.T) (string, *s3.Client) {
	t.Helper()
	ctx := t.Context()
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        image,
			ExposedPorts: []string{"80/tcp"},
			Env: map[string]string{
				"S3PROXY_AUTHORIZATION": "aws-v4",
				"S3PROXY_IDENTITY":      AccessKey,
				"S3PROXY_CREDENTIAL":    SecretKey,
				"JCLOUDS_PROVIDER":      "filesystem-nio2",
			},
			WaitingFor: wait.ForHTTP("/healthz").WithPort("80/tcp").WithStartupTimeout(time.Minute),
		},
		Started: true,
	})
	testcontainers.CleanupContainer(t, ctr)
	require.NoError(t, err)
	endpoint, err := ctr.PortEndpoint(ctx, "80/tcp", "http")
	require.NoError(t, err)
	client := s3.New(s3.Options{
		Region:       Region,
		Credentials:  credentials.NewStaticCredentialsProvider(AccessKey, SecretKey, ""),
		BaseEndpoint: aws.String(endpoint),
		UsePathStyle: true,
	})
	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(Bucket)})
	require.NoError(t, err)
	return endpoint, client
}
