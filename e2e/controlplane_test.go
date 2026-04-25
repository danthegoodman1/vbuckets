package e2e

import (
	"context"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/danthegoodman1/vbuckets/controlplane"
	"github.com/danthegoodman1/vbuckets/http_server"
	apiv1 "github.com/danthegoodman1/vbuckets/v1"
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

const e2eAllowAllPolicyJSON = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`

var hexIDPattern = regexp.MustCompile(`[0-9a-f]{16,}`)

type testControlPlane struct {
	apiv1.UnimplementedControlPlaneServer
	garageEndpoint string
	policyJSON     string
	mu             sync.Mutex
	createdBuckets map[string]time.Time
}

func (s *testControlPlane) LookupCredentials(_ context.Context, req *apiv1.LookupCredentialsRequest) (*apiv1.LookupCredentialsResponse, error) {
	if req.AccessKeyId != e2eVirtualAccessKey {
		return nil, status.Errorf(codes.NotFound, "unknown access key: %s", req.AccessKeyId)
	}
	return &apiv1.LookupCredentialsResponse{
		SecretKey:     e2eVirtualSecretKey,
		IamPolicyJson: s.policyJSON,
		Ttl:           durationpb.New(5 * time.Minute),
	}, nil
}

func (s *testControlPlane) LookupBaseHost(_ context.Context, _ *apiv1.LookupBaseHostRequest) (*apiv1.LookupBaseHostResponse, error) {
	return &apiv1.LookupBaseHostResponse{
		Found: false,
		Ttl:   durationpb.New(5 * time.Minute),
	}, nil
}

func (s *testControlPlane) LookupVBucket(_ context.Context, req *apiv1.LookupVBucketRequest) (*apiv1.LookupVBucketResponse, error) {
	if req.AccessKeyId != e2eVirtualAccessKey {
		return nil, status.Errorf(codes.NotFound, "unknown access key: %s", req.AccessKeyId)
	}
	if req.BucketName == e2eVirtualBucket {
		return s.vbucketResponse("tenant-abc"), nil
	}

	s.mu.Lock()
	_, found := s.createdBuckets[req.BucketName]
	s.mu.Unlock()
	if !found {
		return nil, status.Errorf(codes.NotFound, "unknown bucket: %s", req.BucketName)
	}
	return s.vbucketResponse("created/" + req.BucketName), nil
}

func (s *testControlPlane) CreateVBucket(_ context.Context, req *apiv1.CreateVBucketRequest) (*apiv1.CreateVBucketResponse, error) {
	if req.AccessKeyId != e2eVirtualAccessKey {
		return nil, status.Errorf(codes.NotFound, "unknown access key: %s", req.AccessKeyId)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if req.BucketName == e2eVirtualBucket {
		return nil, status.Errorf(codes.AlreadyExists, "bucket already owned: %s", req.BucketName)
	}
	if _, exists := s.createdBuckets[req.BucketName]; exists {
		return nil, status.Errorf(codes.AlreadyExists, "bucket already owned: %s", req.BucketName)
	}
	s.createdBuckets[req.BucketName] = time.Now().UTC()

	resp := s.vbucketResponse("created/" + req.BucketName)
	return &apiv1.CreateVBucketResponse{
		RealEndpoint:     resp.RealEndpoint,
		RealBucket:       resp.RealBucket,
		RealAccessKey:    resp.RealAccessKey,
		RealSecretKey:    resp.RealSecretKey,
		RealRegion:       resp.RealRegion,
		PathPrefix:       resp.PathPrefix,
		RealUsePathStyle: resp.RealUsePathStyle,
		Ttl:              resp.Ttl,
	}, nil
}

func (s *testControlPlane) ListVBuckets(_ context.Context, req *apiv1.ListVBucketsRequest) (*apiv1.ListVBucketsResponse, error) {
	if req.AccessKeyId != e2eVirtualAccessKey {
		return nil, status.Errorf(codes.NotFound, "unknown access key: %s", req.AccessKeyId)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	resp := &apiv1.ListVBucketsResponse{
		Buckets: []*apiv1.VBucketSummary{{
			BucketName:   e2eVirtualBucket,
			CreationDate: timestamppb.New(time.Unix(0, 0).UTC()),
		}},
	}
	var names []string
	for name := range s.createdBuckets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		resp.Buckets = append(resp.Buckets, &apiv1.VBucketSummary{
			BucketName:   name,
			CreationDate: timestamppb.New(s.createdBuckets[name]),
		})
	}
	return resp, nil
}

func (s *testControlPlane) vbucketResponse(pathPrefix string) *apiv1.LookupVBucketResponse {
	return &apiv1.LookupVBucketResponse{
		RealEndpoint:     s.garageEndpoint,
		RealBucket:       garageBucket,
		RealAccessKey:    garageAccessKey,
		RealSecretKey:    garageSecretKey,
		RealRegion:       "us-east-1",
		PathPrefix:       pathPrefix,
		RealUsePathStyle: true,
		Ttl:              durationpb.New(5 * time.Minute),
	}
}

func (s *testControlPlane) ListenForDeltas(_ *apiv1.ListenForDeltasRequest, stream apiv1.ControlPlane_ListenForDeltasServer) error {
	<-stream.Context().Done()
	return stream.Context().Err()
}

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

type e2eEnv struct {
	ProxyClient  *s3.Client
	DirectClient *s3.Client
}

// setupE2E starts a Garage container, a gRPC control plane server, a real
// controlplane.Client, and the proxy HTTP server -- exercising the full
// production code path.
func setupE2E(t *testing.T) *e2eEnv {
	return setupE2EWithPolicyJSON(t, e2eAllowAllPolicyJSON)
}

func setupE2EWithPolicyJSON(t *testing.T, policyJSON string) *e2eEnv {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

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
	t.Cleanup(func() { require.NoError(t, ctr.Terminate(context.Background())) })

	statusOut := garageCmd(t, ctx, ctr, "status")
	nodeID := hexIDPattern.FindString(statusOut)
	require.NotEmpty(t, nodeID, "could not find node ID in garage status output:\n%s", statusOut)

	garageCmd(t, ctx, ctr, "layout", "assign", nodeID, "--capacity", "100G", "-z", "local")
	garageCmd(t, ctx, ctr, "layout", "apply", "--version", "1")
	garageCmd(t, ctx, ctr, "key", "import", "--yes", "-n", "e2e-key", garageAccessKey, garageSecretKey)
	garageCmd(t, ctx, ctr, "bucket", "create", garageBucket)
	garageCmd(t, ctx, ctr, "bucket", "allow", garageBucket, "--key", "e2e-key", "--read", "--write", "--owner")

	host, err := ctr.Host(ctx)
	require.NoError(t, err)
	mappedPort, err := ctr.MappedPort(ctx, "3900")
	require.NoError(t, err)
	garageEndpoint := "http://" + host + ":" + mappedPort.Port()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	apiv1.RegisterControlPlaneServer(grpcServer, &testControlPlane{
		garageEndpoint: garageEndpoint,
		policyJSON:     policyJSON,
		createdBuckets: make(map[string]time.Time),
	})
	go grpcServer.Serve(lis)
	t.Cleanup(func() {
		// Cancel context first so the ListenForDeltas stream unblocks,
		// then GracefulStop can drain cleanly.
		cancel()
		grpcServer.GracefulStop()
	})

	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	cpClient := controlplane.NewClient(lis.Addr().String(), logger)
	go cpClient.Run(ctx)

	require.Eventually(t, func() bool {
		_, err := cpClient.LookupCredentials(ctx, e2eVirtualAccessKey)
		return err == nil
	}, 10*time.Second, 100*time.Millisecond, "control plane client failed to connect")

	r := chi.NewRouter()
	http_server.RegisterS3Routes(cpClient)(r)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	return &e2eEnv{
		ProxyClient: s3.New(s3.Options{
			Region: "anystringyouwant",
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

func TestE2E_ControlPlane_PutAndGetObject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	t.Parallel()

	ctx := context.Background()
	e := setupE2E(t)

	testKey := "e2e/round-trip.txt"
	testBody := "hello from the control plane e2e test"

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

func TestE2E_ControlPlane_ListObjectsPrefixIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	t.Parallel()

	ctx := context.Background()
	e := setupE2E(t)

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

	_, err := e.DirectClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(garageBucket),
		Key:    aws.String("other-tenant/secret.txt"),
		Body:   strings.NewReader("should not be visible"),
	})
	require.NoError(t, err)

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

	for _, key := range keys {
		assert.NotContains(t, key, "tenant-abc")
		assert.NotContains(t, key, "other-tenant")
	}

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

func TestE2E_ControlPlane_IAMPolicyEnforcedBeforeProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	t.Parallel()

	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::my-virtual-bucket/read/*"
			},
			{
				"Effect": "Allow",
				"Action": "s3:PutObject",
				"Resource": "arn:aws:s3:::my-virtual-bucket/write/*"
			}
		]
	}`

	ctx := context.Background()
	e := setupE2EWithPolicyJSON(t, policyJSON)

	_, err := e.DirectClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(garageBucket),
		Key:    aws.String("tenant-abc/read/existing.txt"),
		Body:   strings.NewReader("readable"),
	})
	require.NoError(t, err)

	getResult, err := e.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(e2eVirtualBucket),
		Key:    aws.String("read/existing.txt"),
	})
	require.NoError(t, err)
	defer getResult.Body.Close()

	body, err := io.ReadAll(getResult.Body)
	require.NoError(t, err)
	assert.Equal(t, "readable", string(body))

	_, err = e.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(e2eVirtualBucket),
		Key:    aws.String("read/denied.txt"),
		Body:   strings.NewReader("should be denied"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")

	_, err = e.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(e2eVirtualBucket),
		Key:    aws.String("write/allowed.txt"),
		Body:   strings.NewReader("written"),
	})
	require.NoError(t, err)

	_, err = e.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(e2eVirtualBucket),
		Key:    aws.String("write/allowed.txt"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")
}

func TestE2E_ControlPlane_CreateAndListVBuckets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	t.Parallel()

	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
			{"Effect": "Allow", "Action": "s3:CreateBucket", "Resource": "arn:aws:s3:::created-vbucket"},
			{"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": "arn:aws:s3:::created-vbucket/*"}
		]
	}`

	ctx := context.Background()
	e := setupE2EWithPolicyJSON(t, policyJSON)

	_, err := e.ProxyClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String("created-vbucket"),
	})
	require.NoError(t, err)

	listResult, err := e.ProxyClient.ListBuckets(ctx, &s3.ListBucketsInput{})
	require.NoError(t, err)
	assert.Contains(t, bucketNames(listResult), "created-vbucket")

	_, err = e.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("created-vbucket"),
		Key:    aws.String("hello.txt"),
		Body:   strings.NewReader("created bucket body"),
	})
	require.NoError(t, err)

	getResult, err := e.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("created-vbucket"),
		Key:    aws.String("hello.txt"),
	})
	require.NoError(t, err)
	defer getResult.Body.Close()

	body, err := io.ReadAll(getResult.Body)
	require.NoError(t, err)
	assert.Equal(t, "created bucket body", string(body))

	_, err = e.ProxyClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String("created-vbucket"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BucketAlreadyOwnedByYou")
}

func TestE2E_ControlPlane_CreateBucketDeniedDoesNotMutate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	t.Parallel()

	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": {
			"Effect": "Allow",
			"Action": "s3:ListAllMyBuckets",
			"Resource": "*"
		}
	}`

	ctx := context.Background()
	e := setupE2EWithPolicyJSON(t, policyJSON)

	_, err := e.ProxyClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String("denied-vbucket"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")

	listResult, err := e.ProxyClient.ListBuckets(ctx, &s3.ListBucketsInput{})
	require.NoError(t, err)
	assert.NotContains(t, bucketNames(listResult), "denied-vbucket")
}

func TestE2E_ControlPlane_ListBucketsDenied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	t.Parallel()

	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": {
			"Effect": "Allow",
			"Action": "s3:CreateBucket",
			"Resource": "arn:aws:s3:::list-denied-vbucket"
		}
	}`

	ctx := context.Background()
	e := setupE2EWithPolicyJSON(t, policyJSON)

	_, err := e.ProxyClient.ListBuckets(ctx, &s3.ListBucketsInput{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")
}

func bucketNames(result *s3.ListBucketsOutput) []string {
	var names []string
	for _, bucket := range result.Buckets {
		if bucket.Name != nil {
			names = append(names, *bucket.Name)
		}
	}
	sort.Strings(names)
	return names
}
