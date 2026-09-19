package http_server

import (
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	"github.com/danthegoodman1/vbuckets/iam"
	"github.com/danthegoodman1/vbuckets/internal/s3test"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	e2eVirtualAccessKey = "AKIAE2ETEST00000001"
	e2eVirtualSecretKey = "e2e-test-secret-key-00000000000000000000"
	e2eVirtualBucket    = "my-virtual-bucket"
)

type e2eEnv struct {
	ProxyClient  *s3.Client
	DirectClient *s3.Client
}

// setupE2E starts S3Proxy and the proxy HTTP server, returning clients for both.
// Registers all cleanup on t.
func setupE2E(t *testing.T) *e2eEnv {
	return setupE2EWithPolicy(t, testAllowAllPolicy)
}

func setupE2EWithPolicy(t *testing.T, policy *iam.Policy) *e2eEnv {
	t.Helper()

	originEndpoint, directClient := s3test.Start(t)

	resolver := &testResolver{
		credentials: func(_ context.Context, accessKeyID string) (*VirtualCredentials, error) {
			if accessKeyID != e2eVirtualAccessKey {
				return nil, fmt.Errorf("unknown access key ID: %s", accessKeyID)
			}
			return &VirtualCredentials{SecretKey: e2eVirtualSecretKey, IAMPolicy: policy}, nil
		},
		baseHost: func(_ context.Context, hostname string) (string, bool, error) {
			return "", false, nil
		},
		vbucket: func(_ context.Context, accessKeyID, bucketName string) (*VBucketConfig, error) {
			if bucketName != e2eVirtualBucket {
				return nil, fmt.Errorf("unknown bucket: %s", bucketName)
			}
			return &VBucketConfig{
				RealEndpoint:     originEndpoint,
				RealBucket:       s3test.Bucket,
				RealAccessKey:    s3test.AccessKey,
				RealSecretKey:    s3test.SecretKey,
				RealRegion:       s3test.Region,
				PathPrefix:       "tenant-abc",
				RealUsePathStyle: true,
				RoutingTokenKey:  testRoutingTokenKey,
			}, nil
		},
	}

	r := chi.NewRouter()
	RegisterS3Routes(resolver)(r)
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
			APIOptions: []func(*middleware.Stack) error{
				awsv4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware,
			},
		}),
		DirectClient: directClient,
	}
}

func TestE2E_PutAndGetObject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	t.Parallel()

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
		Bucket: aws.String(s3test.Bucket),
		Key:    aws.String("tenant-abc/" + testKey),
	})
	require.NoError(t, err)
	defer directResult.Body.Close()

	directBody, err := io.ReadAll(directResult.Body)
	require.NoError(t, err)
	assert.Equal(t, testBody, string(directBody))

	// A permissive origin would hide regressions in outbound re-signing.
	t.Run("origin rejects invalid signature", func(t *testing.T) {
		badClient := s3.New(s3.Options{
			Region:       s3test.Region,
			Credentials:  credentials.NewStaticCredentialsProvider(s3test.AccessKey, "wrong-secret", ""),
			BaseEndpoint: e.DirectClient.Options().BaseEndpoint,
			UsePathStyle: true,
		})
		result, err := badClient.GetObject(t.Context(), &s3.GetObjectInput{
			Bucket: aws.String(s3test.Bucket),
			Key:    aws.String("tenant-abc/" + testKey),
		})
		if result != nil {
			defer result.Body.Close()
		}
		var apiErr smithy.APIError
		require.ErrorAs(t, err, &apiErr)
		assert.Equal(t, "SignatureDoesNotMatch", apiErr.ErrorCode())
	})
}

func TestE2E_CopyObjectSameVirtualBucket(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	t.Parallel()

	ctx := context.Background()
	e := setupE2E(t)

	sourceKey := "copy/source.txt"
	destKey := "copy/dest.txt"
	testBody := "copied through upstream server-side copy"

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

	for _, key := range []string{"tenant-abc/" + sourceKey, "tenant-abc/" + destKey} {
		directResult, err := e.DirectClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(s3test.Bucket),
			Key:    aws.String(key),
		})
		require.NoError(t, err)

		directBody, err := io.ReadAll(directResult.Body)
		require.NoError(t, err)
		require.NoError(t, directResult.Body.Close())
		assert.Equal(t, testBody, string(directBody))
	}

	_, err = e.ProxyClient.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(e2eVirtualBucket),
		Key:        aws.String("copy/cross-bucket.txt"),
		CopySource: aws.String("other-virtual-bucket/" + sourceKey),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "InvalidRequest")

	_, err = e.ProxyClient.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
		Bucket:     aws.String(e2eVirtualBucket),
		Key:        aws.String("copy/multipart.txt"),
		CopySource: aws.String(e2eVirtualBucket + "/" + sourceKey),
		PartNumber: aws.Int32(1),
		UploadId:   aws.String("upload-1"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "InvalidRequest")
}

func TestE2E_ListObjectsPrefixIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	t.Parallel()

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
		Bucket: aws.String(s3test.Bucket),
		Key:    aws.String("other-tenant/secret.txt"),
		Body:   strings.NewReader("should not be visible"),
	})
	require.NoError(t, err)

	// Sanity check: listing the real bucket directly (no prefix) returns all 3
	// objects. This proves the foreign object exists and the proxy is the thing
	// providing isolation, not an accident of test setup.
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

func TestE2E_IAMPolicyEnforcedBeforeProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	t.Parallel()

	policy := mustParseTestPolicy(`{
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
	}`)

	ctx := context.Background()
	e := setupE2EWithPolicy(t, policy)

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

	_, err = e.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(e2eVirtualBucket),
		Key:    aws.String("outside/denied.txt"),
		Body:   strings.NewReader("should be denied"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")
}
