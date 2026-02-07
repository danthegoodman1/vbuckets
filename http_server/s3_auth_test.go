package http_server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAccessKey = "AKIAIOSFODNN7EXAMPLE"
	testSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	testBucket    = "test-bucket"
	testRegion    = "us-east-1"
)

type testResolver struct {
	credentials func(ctx context.Context, accessKeyID string) (*VirtualCredentials, error)
	baseHost    func(ctx context.Context, hostname string) (string, bool, error)
	vbucket     func(ctx context.Context, accessKeyID, bucketName string) (*VBucketConfig, error)
}

func (r *testResolver) LookupCredentials(ctx context.Context, accessKeyID string) (*VirtualCredentials, error) {
	return r.credentials(ctx, accessKeyID)
}

func (r *testResolver) LookupBaseHost(ctx context.Context, hostname string) (string, bool, error) {
	return r.baseHost(ctx, hostname)
}

func (r *testResolver) LookupVBucket(ctx context.Context, accessKeyID, bucketName string) (*VBucketConfig, error) {
	return r.vbucket(ctx, accessKeyID, bucketName)
}

func newTestResolver() *testResolver {
	return &testResolver{
		credentials: func(_ context.Context, accessKeyID string) (*VirtualCredentials, error) {
			if accessKeyID != testAccessKey {
				return nil, fmt.Errorf("unknown access key ID: %s", accessKeyID)
			}
			return &VirtualCredentials{SecretKey: testSecretKey}, nil
		},
		baseHost: func(_ context.Context, hostname string) (string, bool, error) {
			return "", false, nil
		},
		vbucket: func(_ context.Context, accessKeyID, bucketName string) (*VBucketConfig, error) {
			return &VBucketConfig{}, nil
		},
	}
}

// newTestServer returns an httptest.Server with S3Auth middleware wrapping
// a handler that returns minimal valid responses based on the HTTP method.
func newTestServer(t *testing.T, resolver Resolver) *httptest.Server {
	t.Helper()

	handler := S3Auth(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			w.Header().Set("ETag", `"d41d8cd98f00b204e9800998ecf8427e"`)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			body := []byte("test-object-content")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
			w.Header().Set("ETag", `"abc123"`)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			w.Write(body)
		case http.MethodHead:
			w.Header().Set("Content-Length", "19")
			w.Header().Set("ETag", `"abc123"`)
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))

	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

func emptyPayloadHash() string {
	return fmt.Sprintf("%x", sha256.Sum256(nil))
}

func signedRequest(t *testing.T, method, url string, body []byte, payloadHash string, creds aws.Credentials) *http.Request {
	t.Helper()

	var bodyReader *bytes.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	require.NoError(t, err)

	req.Header.Set("x-amz-content-sha256", payloadHash)

	signer := awsv4.NewSigner()
	require.NoError(t, signer.SignHTTP(context.Background(), creds, req, payloadHash, "s3", testRegion, time.Now()))

	return req
}

var validCreds = aws.Credentials{
	AccessKeyID:     testAccessKey,
	SecretAccessKey: testSecretKey,
}

func TestSigV4_RawSigner_GET(t *testing.T) {
	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	req := signedRequest(t, http.MethodGet, ts.URL+"/"+testBucket+"/my-key.txt", nil, emptyPayloadHash(), validCreds)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSigV4_RawSigner_PUT_WithBody(t *testing.T) {
	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	body := []byte("hello world, this is a test upload")
	payloadHash := fmt.Sprintf("%x", sha256.Sum256(body))

	req := signedRequest(t, http.MethodPut, ts.URL+"/"+testBucket+"/upload/test.txt", body, payloadHash, validCreds)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSigV4_RawSigner_UnsignedPayload(t *testing.T) {
	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	body := []byte("unsigned payload body")
	req := signedRequest(t, http.MethodPut, ts.URL+"/"+testBucket+"/unsigned.bin", body, "UNSIGNED-PAYLOAD", validCreds)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSigV4_RawSigner_WithQueryParams(t *testing.T) {
	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	req := signedRequest(t, http.MethodGet, ts.URL+"/"+testBucket+"?list-type=2&prefix=photos/&max-keys=100", nil, emptyPayloadHash(), validCreds)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSigV4_RawSigner_InvalidCredentials(t *testing.T) {
	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	badCreds := aws.Credentials{
		AccessKeyID:     testAccessKey,
		SecretAccessKey: "wrong-secret-key-should-fail",
	}
	req := signedRequest(t, http.MethodGet, ts.URL+"/"+testBucket+"/secret.txt", nil, emptyPayloadHash(), badCreds)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestSigV4_RawSigner_UnknownAccessKey(t *testing.T) {
	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	unknownCreds := aws.Credentials{
		AccessKeyID:     "AKIAI_UNKNOWN_KEY",
		SecretAccessKey: testSecretKey,
	}
	req := signedRequest(t, http.MethodGet, ts.URL+"/"+testBucket+"/test.txt", nil, emptyPayloadHash(), unknownCreds)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestSigV4_S3Client_PutObject(t *testing.T) {
	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	client := s3.New(s3.Options{
		Region: testRegion,
		Credentials: credentials.NewStaticCredentialsProvider(
			testAccessKey, testSecretKey, "",
		),
		BaseEndpoint: aws.String(ts.URL),
		UsePathStyle: true,
	})

	_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("sdk-test/hello.txt"),
		Body:   strings.NewReader("hello from the SDK"),
	})
	if err != nil {
		errStr := err.Error()
		// Signature errors are the only ones we care about -- response parsing
		// errors are expected since we return a minimal mock response
		assert.False(t,
			strings.Contains(errStr, "SignatureDoesNotMatch") || strings.Contains(errStr, "403") || strings.Contains(errStr, "AccessDenied"),
			"signature verification failed: %v", err,
		)
		t.Logf("non-signature error (signature was accepted): %v", err)
	}
}

func TestSigV4_S3Client_HeadObject(t *testing.T) {
	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	client := s3.New(s3.Options{
		Region: testRegion,
		Credentials: credentials.NewStaticCredentialsProvider(
			testAccessKey, testSecretKey, "",
		),
		BaseEndpoint: aws.String(ts.URL),
		UsePathStyle: true,
	})

	_, err := client.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("sdk-test/hello.txt"),
	})
	if err != nil {
		errStr := err.Error()
		assert.False(t,
			strings.Contains(errStr, "SignatureDoesNotMatch") || strings.Contains(errStr, "403") || strings.Contains(errStr, "AccessDenied"),
			"signature verification failed: %v", err,
		)
		t.Logf("non-signature error (signature was accepted): %v", err)
	}
}

func TestSigV4_VHostStyle(t *testing.T) {
	resolver := newTestResolver()
	resolver.baseHost = func(_ context.Context, hostname string) (string, bool, error) {
		if hostname == "s3.test.local" || strings.HasSuffix(hostname, ".s3.test.local") {
			return "s3.test.local", true, nil
		}
		return "", false, nil
	}

	handler := S3Auth(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, getIsVHost(r.Context()), "expected vhost-style request")
		assert.Equal(t, testBucket, getBucketName(r.Context()))
		assert.Equal(t, "my-key.txt", getObjectKey(r.Context()))
		w.WriteHeader(http.StatusOK)
	}))

	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/my-key.txt", nil)
	require.NoError(t, err)
	// Override Host to simulate vhost-style while still connecting to test server
	req.Host = testBucket + ".s3.test.local"

	payloadHash := emptyPayloadHash()
	req.Header.Set("x-amz-content-sha256", payloadHash)

	signer := awsv4.NewSigner()
	require.NoError(t, signer.SignHTTP(context.Background(), validCreds, req, payloadHash, "s3", testRegion, time.Now()))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
