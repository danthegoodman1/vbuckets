package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
	"github.com/danthegoodman1/vbuckets/internal/s3test"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/danthegoodman1/vbuckets/api/v1"
	"github.com/danthegoodman1/vbuckets/controlplane"
	"github.com/danthegoodman1/vbuckets/http_server"
)

const (
	e2eVirtualAccessKey = "AKIAE2ETEST00000001"
	e2eVirtualSecretKey = "e2e-test-secret-key-00000000000000000000"
	e2eVirtualBucket    = "my-virtual-bucket"
)

const e2eAllowAllPolicyJSON = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`

type testIdentity struct {
	secret, policyJSON string
	buckets            map[string]string // virtual name -> physical prefix; independent of IAM
}

type testControlPlane struct {
	apiv1.UnimplementedControlPlaneServer
	originEndpoint    string
	identities        map[string]*testIdentity
	credentialLookups map[string]int
	mu                sync.Mutex
	createdBuckets    map[string]time.Time
	revision          uint64
	changes           chan *apiv1.WatchEvent
}

func (s *testControlPlane) LookupCredentials(_ context.Context, req *apiv1.LookupCredentialsRequest) (*apiv1.LookupCredentialsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.credentialLookups == nil {
		s.credentialLookups = make(map[string]int)
	}
	s.credentialLookups[req.AccessKeyId]++
	identity, found := s.identities[req.AccessKeyId]
	if !found {
		return &apiv1.LookupCredentialsResponse{Revision: s.revision, NegativeTtl: durationpb.New(time.Minute)}, nil
	}
	return &apiv1.LookupCredentialsResponse{SecretKey: identity.secret, IamPolicyJson: identity.policyJSON, Ttl: durationpb.New(5 * time.Minute), Found: true, Revision: s.revision}, nil
}

func (s *testControlPlane) LookupVBucket(_ context.Context, req *apiv1.LookupVBucketRequest) (*apiv1.LookupVBucketResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if identity := s.identities[req.AccessKeyId]; identity != nil {
		if prefix, found := identity.buckets[req.BucketName]; found {
			return s.vbucketResponse(prefix, s.revision), nil
		}
	}
	return &apiv1.LookupVBucketResponse{Revision: s.revision, NegativeTtl: durationpb.New(time.Minute)}, nil
}

func (s *testControlPlane) CreateVBucket(_ context.Context, req *apiv1.CreateVBucketRequest) (*apiv1.CreateVBucketResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity := s.identities[req.AccessKeyId]
	if identity == nil {
		return nil, status.Error(codes.NotFound, "unknown access key")
	}
	for _, other := range s.identities {
		if _, found := other.buckets[req.BucketName]; found {
			return nil, status.Error(codes.AlreadyExists, "bucket already exists")
		}
	}
	s.createdBuckets[req.BucketName] = time.Now().UTC()
	identity.buckets[req.BucketName] = "created/" + req.BucketName
	s.revision++
	s.changes <- &apiv1.WatchEvent{Revision: s.revision, Cursor: fmt.Sprintf("cursor-%d", s.revision), Event: &apiv1.WatchEvent_Vbucket{Vbucket: &apiv1.VBucketDelta{AccessKeyId: req.AccessKeyId, BucketName: req.BucketName}}}
	return &apiv1.CreateVBucketResponse{Revision: s.revision}, nil
}

func (s *testControlPlane) ListVBuckets(_ context.Context, req *apiv1.ListVBucketsRequest) (*apiv1.ListVBucketsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity := s.identities[req.AccessKeyId]
	if identity == nil {
		return nil, status.Error(codes.NotFound, "unknown access key")
	}
	resp := &apiv1.ListVBucketsResponse{Revision: s.revision}
	var names []string
	for name := range identity.buckets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		created, found := s.createdBuckets[name]
		if !found {
			created = time.Unix(0, 0).UTC()
		}
		resp.Buckets = append(resp.Buckets, &apiv1.VBucketSummary{BucketName: name, CreationDate: timestamppb.New(created)})
	}
	return resp, nil
}

// Single-proxy test fixture only: the buffered channel stands in for the
// production control plane's durable, broadcast revision log.
func (s *testControlPlane) setPolicy(accessKey, policyJSON string) (uint64, error) {
	if _, err := http_server.ParseS3IAMPolicyJSON(policyJSON); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	identity := s.identities[accessKey]
	if identity == nil {
		return 0, fmt.Errorf("unknown test access key")
	}
	identity.policyJSON = policyJSON
	s.revision++
	s.changes <- &apiv1.WatchEvent{Revision: s.revision, Cursor: fmt.Sprintf("cursor-%d", s.revision), Event: &apiv1.WatchEvent_Credentials{Credentials: &apiv1.CredentialsDelta{AccessKeyId: accessKey}}}
	return s.revision, nil
}

func (s *testControlPlane) vbucketResponse(pathPrefix string, revision uint64) *apiv1.LookupVBucketResponse {
	return &apiv1.LookupVBucketResponse{
		RealEndpoint:     s.originEndpoint,
		RealBucket:       s3test.Bucket,
		RealAccessKey:    s3test.AccessKey,
		RealSecretKey:    s3test.SecretKey,
		RealRegion:       s3test.Region,
		PathPrefix:       pathPrefix,
		RealUsePathStyle: true,
		RoutingTokenKey:  []byte("0123456789abcdef0123456789abcdef"),
		Ttl:              durationpb.New(5 * time.Minute),
		Found:            true,
		Revision:         revision,
	}
}

func (s *testControlPlane) WatchState(_ *apiv1.WatchStateRequest, stream apiv1.ControlPlane_WatchStateServer) error {
	s.mu.Lock()
	revision := s.revision
	s.mu.Unlock()
	if err := stream.Send(&apiv1.WatchEvent{Revision: revision, Event: &apiv1.WatchEvent_SnapshotBegin{SnapshotBegin: &apiv1.SnapshotBegin{}}}); err != nil {
		return err
	}
	cursor := fmt.Sprintf("cursor-%d", revision)
	if err := stream.Send(&apiv1.WatchEvent{Revision: revision, Cursor: cursor, Event: &apiv1.WatchEvent_SynchronizationBarrier{SynchronizationBarrier: &apiv1.SynchronizationBarrier{}}}); err != nil {
		return err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case event := <-s.changes:
			if err := stream.Send(event); err != nil {
				return err
			}
			revision, cursor = event.Revision, event.Cursor
		case <-ticker.C:
			if err := stream.Send(&apiv1.WatchEvent{Revision: revision, Cursor: cursor, Event: &apiv1.WatchEvent_Heartbeat{Heartbeat: &apiv1.Heartbeat{}}}); err != nil {
				return err
			}
		}
	}
}

type e2eEnv struct {
	ProxyClient  *s3.Client
	DirectClient *s3.Client
}

// setupE2E starts a S3Proxy container, a gRPC control plane server, a real
// controlplane.Client, and the proxy HTTP server -- exercising the full
// production code path.
func setupE2E(t *testing.T) *e2eEnv {
	return setupE2EWithPolicyJSON(t, e2eAllowAllPolicyJSON)
}

func setupE2EWithPolicyJSON(t *testing.T, policyJSON string) *e2eEnv {
	t.Helper()

	originEndpoint, directClient := s3test.Start(t)

	_, ts := setupControlPlaneProxy(t, &testControlPlane{
		originEndpoint: originEndpoint,
		identities:     map[string]*testIdentity{e2eVirtualAccessKey: {secret: e2eVirtualSecretKey, policyJSON: policyJSON, buckets: map[string]string{e2eVirtualBucket: "tenant-abc"}}},
		createdBuckets: make(map[string]time.Time), revision: 1, changes: make(chan *apiv1.WatchEvent, 16),
	})

	return &e2eEnv{
		ProxyClient: s3.New(s3.Options{
			Region: "anystringyouwant",
			Credentials: credentials.NewStaticCredentialsProvider(
				e2eVirtualAccessKey, e2eVirtualSecretKey, "",
			),
			BaseEndpoint: aws.String(ts.URL),
			UsePathStyle: true,
			APIOptions: []func(*middleware.Stack) error{
				awsv4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware,
			},
		}),
		DirectClient: directClient,
	}
}

// Shared by S3Proxy tests and the fast per-key conformance tests. The actual
// Client, watch, caches, production HTTP wrapper, IAM, and proxy all run here.
func setupControlPlaneProxy(t *testing.T, implementation *testControlPlane) (*controlplane.Client, *httptest.Server) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	apiv1.RegisterControlPlaneServer(server, implementation)
	go server.Serve(lis)
	ctx, cancel := context.WithCancel(t.Context())
	cp := controlplane.NewClient(lis.Addr().String(), zerolog.Nop())
	done := make(chan struct{})
	go func() { defer close(done); cp.Run(ctx) }()
	t.Cleanup(func() { cancel(); server.Stop(); <-done })
	require.Eventually(t, cp.Ready, 5*time.Second, time.Millisecond, "control plane failed to synchronize")
	proxy := httptest.NewServer(http_server.NewServer(":0", http_server.RegisterS3Routes(cp)).Handler)
	t.Cleanup(proxy.Close)
	return cp, proxy
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
		Bucket: aws.String(s3test.Bucket),
		Key:    aws.String("tenant-abc/" + testKey),
	})
	require.NoError(t, err)
	defer directResult.Body.Close()

	directBody, err := io.ReadAll(directResult.Body)
	require.NoError(t, err)
	assert.Equal(t, testBody, string(directBody))
}

func TestE2E_ControlPlane_CopyObjectSameVirtualBucket(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	t.Parallel()

	ctx := context.Background()
	e := setupE2E(t)

	sourceKey := "copy/source.txt"
	destKey := "copy/dest.txt"
	testBody := "copied through control plane proxy path"

	_, err := e.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(e2eVirtualBucket),
		Key:    aws.String(sourceKey),
		Body:   strings.NewReader(testBody),
	})
	require.NoError(t, err)

	_, err = e.ProxyClient.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(e2eVirtualBucket),
		Key:        aws.String(destKey),
		CopySource: aws.String(e2eVirtualBucket + "/" + sourceKey),
	})
	require.NoError(t, err)

	getResult, err := e.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(e2eVirtualBucket),
		Key:    aws.String(destKey),
	})
	require.NoError(t, err)
	defer getResult.Body.Close()

	body, err := io.ReadAll(getResult.Body)
	require.NoError(t, err)
	assert.Equal(t, testBody, string(body))

	directResult, err := e.DirectClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s3test.Bucket),
		Key:    aws.String("tenant-abc/" + destKey),
	})
	require.NoError(t, err)
	defer directResult.Body.Close()

	directBody, err := io.ReadAll(directResult.Body)
	require.NoError(t, err)
	assert.Equal(t, testBody, string(directBody))

	_, err = e.ProxyClient.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(e2eVirtualBucket),
		Key:        aws.String("copy/cross-bucket.txt"),
		CopySource: aws.String("other-virtual-bucket/" + sourceKey),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "InvalidRequest")
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
		Bucket: aws.String(s3test.Bucket),
		Key:    aws.String("other-tenant/secret.txt"),
		Body:   strings.NewReader("should not be visible"),
	})
	require.NoError(t, err)

	directList, err := e.DirectClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(s3test.Bucket),
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
		Bucket: aws.String(s3test.Bucket),
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
