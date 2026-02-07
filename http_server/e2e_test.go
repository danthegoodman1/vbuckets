package http_server

import (
	"context"
	"io"
	"net/http/httptest"
	"regexp"
	"sort"
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

type e2eEnv struct {
	ProxyClient  *s3.Client
	DirectClient *s3.Client
}

// setupE2E starts a Garage container, configures the vbuckets env vars, starts
// the proxy httptest server, and returns S3 clients for both the proxy and
// the real backend. Registers all cleanup on t.
func setupE2E(t *testing.T) *e2eEnv {
	t.Helper()

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
	t.Cleanup(func() { require.NoError(t, ctr.Terminate(ctx)) })

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

	saved := snapshotEnv()
	t.Cleanup(func() { restoreEnv(saved) })

	garageEndpoint := "http://" + host + ":" + mappedPort.Port()

	env.VirtualAccessKeyID = e2eVirtualAccessKey
	env.VirtualSecretAccessKey = e2eVirtualSecretKey
	env.VirtualBucketName = e2eVirtualBucket
	env.RealS3Endpoint = garageEndpoint
	env.RealBucket = garageBucket
	env.RealAccessKeyID = garageAccessKey
	env.RealSecretAccessKey = garageSecretKey
	env.RealRegion = "us-east-1"
	env.RealUsePathStyle = true
	env.RealPathPrefix = "tenant-abc"
	env.S3BaseHost = ""

	r := chi.NewRouter()
	RegisterS3Routes(r)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	return &e2eEnv{
		ProxyClient: s3.New(s3.Options{
			Region: "us-east-1",
			Credentials: credentials.NewStaticCredentialsProvider(
				e2eVirtualAccessKey, e2eVirtualSecretKey, "",
			),
			BaseEndpoint: aws.String(ts.URL),
			UsePathStyle: true,
		}),
		DirectClient: s3.New(s3.Options{
			Region: "us-east-1",
			Credentials: credentials.NewStaticCredentialsProvider(
				garageAccessKey, garageSecretKey, "",
			),
			BaseEndpoint: aws.String(garageEndpoint),
			UsePathStyle: true,
		}),
	}
}

func TestE2E_PutAndGetObject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	ctx := context.Background()
	e := setupE2E(t)

	testKey := "e2e/round-trip.txt"
	testBody := "hello from the e2e test"

	_, err := e.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(e2eVirtualBucket),
		Key:    aws.String(testKey),
		Body:   strings.NewReader(testBody),
	})
	require.NoError(t, err)

	getResult, err := e.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(e2eVirtualBucket),
		Key:    aws.String(testKey),
	})
	require.NoError(t, err)
	defer getResult.Body.Close()

	body, err := io.ReadAll(getResult.Body)
	require.NoError(t, err)
	assert.Equal(t, testBody, string(body))

	directResult, err := e.DirectClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(garageBucket),
		Key:    aws.String("tenant-abc/" + testKey),
	})
	require.NoError(t, err)
	defer directResult.Body.Close()

	directBody, err := io.ReadAll(directResult.Body)
	require.NoError(t, err)
	assert.Equal(t, testBody, string(directBody))
}

func TestE2E_ListObjectsPrefixIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	ctx := context.Background()
	e := setupE2E(t)

	// Put two objects through the proxy (they land under tenant-abc/ in the real bucket)
	for _, obj := range []struct{ key, body string }{
		{"a.txt", "content-a"},
		{"dir/b.txt", "content-b"},
	} {
		_, err := e.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(e2eVirtualBucket),
			Key:    aws.String(obj.key),
			Body:   strings.NewReader(obj.body),
		})
		require.NoError(t, err)
	}

	// Put a foreign object directly in the real bucket (outside the tenant prefix)
	_, err := e.DirectClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(garageBucket),
		Key:    aws.String("other-tenant/secret.txt"),
		Body:   strings.NewReader("should not be visible"),
	})
	require.NoError(t, err)

	// Sanity check: listing the real bucket directly (no prefix) returns all 3
	// objects. This proves the foreign object exists and the proxy is the thing
	// providing isolation, not an accident of test setup.
	directList, err := e.DirectClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(garageBucket),
	})
	require.NoError(t, err)

	var allKeys []string
	for _, obj := range directList.Contents {
		allKeys = append(allKeys, *obj.Key)
	}
	sort.Strings(allKeys)
	assert.Equal(t, []string{
		"other-tenant/secret.txt",
		"tenant-abc/a.txt",
		"tenant-abc/dir/b.txt",
	}, allKeys)

	// List through the proxy -- should only see the tenant's objects, with clean keys
	listResult, err := e.ProxyClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(e2eVirtualBucket),
	})
	require.NoError(t, err)

	var keys []string
	for _, obj := range listResult.Contents {
		keys = append(keys, *obj.Key)
	}
	sort.Strings(keys)

	assert.Equal(t, []string{"a.txt", "dir/b.txt"}, keys)

	// No key should contain the internal prefix or the foreign tenant's path
	for _, key := range keys {
		assert.NotContains(t, key, "tenant-abc")
		assert.NotContains(t, key, "other-tenant")
	}

	// List with a sub-prefix through the proxy
	listResult, err = e.ProxyClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(e2eVirtualBucket),
		Prefix: aws.String("dir/"),
	})
	require.NoError(t, err)

	keys = nil
	for _, obj := range listResult.Contents {
		keys = append(keys, *obj.Key)
	}
	assert.Equal(t, []string{"dir/b.txt"}, keys)
}
