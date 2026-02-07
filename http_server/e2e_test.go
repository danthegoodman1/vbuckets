package http_server

import (
	"context"
	"io"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/danthegoodman1/vbuckets/env"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

const garageToml = `
rpc_bind_addr = "[::]:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "0000000000000000000000000000000000000000000000000000000000000000"

metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "lmdb"

replication_factor = 1
compression_level = 2

[s3_api]
api_bind_addr = "[::]:3900"
s3_region = "us-east-1"

[s3_web]
bind_addr = "[::]:3902"
root_domain = ".s3-web.local"

[admin]
api_bind_addr = "[::]:3903"
admin_token = "admin_token"
`

const (
	garageAccessKey = "GK000000000000000000000001"
	garageSecretKey = "dceca21654db35d95f9e8392b7abb2612a2814b11a733a1f0d904fdd585e7534"
	garageBucket    = "e2e-bucket"

	e2eVirtualAccessKey = "AKIAE2ETEST00000001"
	e2eVirtualSecretKey = "e2e-test-secret-key-00000000000000000000"
	e2eVirtualBucket    = "my-virtual-bucket"
)

func garageCmd(t *testing.T, ctx context.Context, ctr testcontainers.Container, args ...string) string {
	t.Helper()
	cmd := append([]string{"/garage"}, args...)
	code, reader, err := ctr.Exec(ctx, cmd, tcexec.Multiplexed())
	require.NoError(t, err)
	out, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equalf(t, 0, code, "garage %v failed (exit %d): %s", args, code, string(out))
	return string(out)
}

// nodeIDFromStatus extracts the first hex node ID from `garage status` output.
var hexIDPattern = regexp.MustCompile(`[0-9a-f]{16,}`)

func nodeIDFromStatus(status string) string {
	return hexIDPattern.FindString(status)
}

type envSnapshot struct {
	VirtualAccessKeyID     string
	VirtualSecretAccessKey string
	VirtualBucketName      string
	RealS3Endpoint         string
	RealBucket             string
	RealAccessKeyID        string
	RealSecretAccessKey    string
	RealRegion             string
	RealUsePathStyle       bool
	RealPathPrefix         string
	S3BaseHost             string
}

func snapshotEnv() envSnapshot {
	return envSnapshot{
		VirtualAccessKeyID:     env.VirtualAccessKeyID,
		VirtualSecretAccessKey: env.VirtualSecretAccessKey,
		VirtualBucketName:      env.VirtualBucketName,
		RealS3Endpoint:         env.RealS3Endpoint,
		RealBucket:             env.RealBucket,
		RealAccessKeyID:        env.RealAccessKeyID,
		RealSecretAccessKey:    env.RealSecretAccessKey,
		RealRegion:             env.RealRegion,
		RealUsePathStyle:       env.RealUsePathStyle,
		RealPathPrefix:         env.RealPathPrefix,
		S3BaseHost:             env.S3BaseHost,
	}
}

func restoreEnv(s envSnapshot) {
	env.VirtualAccessKeyID = s.VirtualAccessKeyID
	env.VirtualSecretAccessKey = s.VirtualSecretAccessKey
	env.VirtualBucketName = s.VirtualBucketName
	env.RealS3Endpoint = s.RealS3Endpoint
	env.RealBucket = s.RealBucket
	env.RealAccessKeyID = s.RealAccessKeyID
	env.RealSecretAccessKey = s.RealSecretAccessKey
	env.RealRegion = s.RealRegion
	env.RealUsePathStyle = s.RealUsePathStyle
	env.RealPathPrefix = s.RealPathPrefix
	env.S3BaseHost = s.S3BaseHost
}

func TestE2E_PutAndGetObject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	ctx := context.Background()

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "dxflrs/garage:v2.1.0",
			ExposedPorts: []string{"3900/tcp"},
			Env:          map[string]string{"GARAGE_ALLOW_WORLD_READABLE_SECRETS": "true"},
			Files: []testcontainers.ContainerFile{{
				Reader:            strings.NewReader(garageToml),
				ContainerFilePath: "/etc/garage.toml",
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForListeningPort("3900/tcp").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, ctr.Terminate(ctx))
	})

	// Configure Garage: layout, key, bucket
	status := garageCmd(t, ctx, ctr, "status")
	nodeID := nodeIDFromStatus(status)
	require.NotEmpty(t, nodeID, "could not find node ID in garage status output:\n%s", status)

	garageCmd(t, ctx, ctr, "layout", "assign", nodeID, "--capacity", "100G", "-z", "local")
	garageCmd(t, ctx, ctr, "layout", "apply", "--version", "1")
	garageCmd(t, ctx, ctr, "key", "import", "--yes", "-n", "e2e-key", garageAccessKey, garageSecretKey)
	garageCmd(t, ctx, ctr, "bucket", "create", garageBucket)
	garageCmd(t, ctx, ctr, "bucket", "allow", garageBucket, "--key", "e2e-key", "--read", "--write", "--owner")

	host, err := ctr.Host(ctx)
	require.NoError(t, err)
	mappedPort, err := ctr.MappedPort(ctx, "3900")
	require.NoError(t, err)

	// Point vbuckets at the Garage backend
	saved := snapshotEnv()
	t.Cleanup(func() { restoreEnv(saved) })

	env.VirtualAccessKeyID = e2eVirtualAccessKey
	env.VirtualSecretAccessKey = e2eVirtualSecretKey
	env.VirtualBucketName = e2eVirtualBucket
	env.RealS3Endpoint = "http://" + host + ":" + mappedPort.Port()
	env.RealBucket = garageBucket
	env.RealAccessKeyID = garageAccessKey
	env.RealSecretAccessKey = garageSecretKey
	env.RealRegion = "us-east-1"
	env.RealUsePathStyle = true
	env.RealPathPrefix = "tenant-abc"
	env.S3BaseHost = ""

	garageEndpoint := "http://" + host + ":" + mappedPort.Port()

	// Start vbuckets proxy
	r := chi.NewRouter()
	RegisterS3Routes(r)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	// S3 client with virtual credentials pointed at the proxy
	proxyClient := s3.New(s3.Options{
		Region: "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider(
			e2eVirtualAccessKey, e2eVirtualSecretKey, "",
		),
		BaseEndpoint: aws.String(ts.URL),
		UsePathStyle: true,
	})

	// Direct client with real credentials pointed at Garage
	directClient := s3.New(s3.Options{
		Region: "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider(
			garageAccessKey, garageSecretKey, "",
		),
		BaseEndpoint: aws.String(garageEndpoint),
		UsePathStyle: true,
	})

	testKey := "e2e/round-trip.txt"
	testBody := "hello from the e2e test"

	// Write through the proxy
	_, err = proxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(e2eVirtualBucket),
		Key:    aws.String(testKey),
		Body:   strings.NewReader(testBody),
	})
	require.NoError(t, err)

	// Read back through the proxy
	getResult, err := proxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(e2eVirtualBucket),
		Key:    aws.String(testKey),
	})
	require.NoError(t, err)
	defer getResult.Body.Close()

	body, err := io.ReadAll(getResult.Body)
	require.NoError(t, err)
	assert.Equal(t, testBody, string(body))

	// Verify the object landed at the prefixed path in the real bucket
	directResult, err := directClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(garageBucket),
		Key:    aws.String("tenant-abc/" + testKey),
	})
	require.NoError(t, err)
	defer directResult.Body.Close()

	directBody, err := io.ReadAll(directResult.Body)
	require.NoError(t, err)
	assert.Equal(t, testBody, string(directBody))
}
