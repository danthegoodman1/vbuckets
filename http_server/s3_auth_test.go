package http_server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
	"github.com/danthegoodman1/vbuckets/env"
	"github.com/danthegoodman1/vbuckets/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAccessKey = "AKIAIOSFODNN7EXAMPLE"
	testSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	testBucket    = "test-bucket"
	testRegion    = "us-east-1"
)

const allowAllS3PolicyJSON = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`

var testAllowAllPolicy = mustParseTestPolicy(allowAllS3PolicyJSON)
var testRoutingTokenKey = []byte("0123456789abcdef0123456789abcdef")

func mustParseTestPolicy(policyJSON string) *iam.Policy {
	policy, err := ParseS3IAMPolicyJSON(policyJSON)
	if err != nil {
		panic(err)
	}
	return policy
}

type testResolver struct {
	credentials func(ctx context.Context, accessKeyID string) (*VirtualCredentials, error)
	baseHost    func(ctx context.Context, hostname string) (string, bool, error)
	vbucket     func(ctx context.Context, accessKeyID, bucketName string) (*VBucketConfig, error)
	create      func(ctx context.Context, accessKeyID, bucketName, locationConstraint string) (*VBucketConfig, error)
	list        func(ctx context.Context, accessKeyID string) ([]ListedVBucket, error)
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

func (r *testResolver) CreateVBucket(ctx context.Context, accessKeyID, bucketName, locationConstraint string) (*VBucketConfig, error) {
	return r.create(ctx, accessKeyID, bucketName, locationConstraint)
}

func (r *testResolver) ListVBuckets(ctx context.Context, accessKeyID string) ([]ListedVBucket, error) {
	return r.list(ctx, accessKeyID)
}

func newTestResolver() *testResolver {
	return &testResolver{
		credentials: func(_ context.Context, accessKeyID string) (*VirtualCredentials, error) {
			if accessKeyID != testAccessKey {
				return nil, fmt.Errorf("unknown access key ID: %s", accessKeyID)
			}
			return &VirtualCredentials{SecretKey: testSecretKey, IAMPolicy: testAllowAllPolicy}, nil
		},
		baseHost: func(_ context.Context, hostname string) (string, bool, error) {
			return "", false, nil
		},
		vbucket: func(_ context.Context, accessKeyID, bucketName string) (*VBucketConfig, error) {
			return &VBucketConfig{}, nil
		},
		create: func(_ context.Context, accessKeyID, bucketName, locationConstraint string) (*VBucketConfig, error) {
			return validTestVBucketConfig(), nil
		},
		list: func(_ context.Context, accessKeyID string) ([]ListedVBucket, error) {
			return nil, nil
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
	return signedRequestAtTimeWithHeaders(t, method, url, body, payloadHash, creds, time.Now().UTC(), nil)
}

func signedRequestAtTime(t *testing.T, method, url string, body []byte, payloadHash string, creds aws.Credentials, signedAt time.Time) *http.Request {
	return signedRequestAtTimeWithHeaders(t, method, url, body, payloadHash, creds, signedAt, nil)
}

func signedRequestWithHeaders(t *testing.T, method, url string, body []byte, payloadHash string, creds aws.Credentials, headers map[string]string) *http.Request {
	return signedRequestAtTimeWithHeaders(t, method, url, body, payloadHash, creds, time.Now().UTC(), headers)
}

func signedRequestAtTimeWithHeaders(t *testing.T, method, url string, body []byte, payloadHash string, creds aws.Credentials, signedAt time.Time, headers map[string]string) *http.Request {
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
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	signer := awsv4.NewSigner(func(options *awsv4.SignerOptions) {
		options.DisableURIPathEscaping = true
	})
	require.NoError(t, signer.SignHTTP(context.Background(), creds, req, payloadHash, "s3", testRegion, signedAt))

	return req
}

func parsedAuthInfo(t *testing.T, req *http.Request) *AuthInfo {
	t.Helper()
	info, err := parseAuthorizationHeader(req.Header.Get("Authorization"))
	require.NoError(t, err)
	return info
}

func recomputeTestSignature(req *http.Request, info *AuthInfo, secret string) {
	canonicalRequest := buildCanonicalRequest(req, info.SignedHeaders)
	stringToSign := buildStringToSign(req.Header.Get("X-Amz-Date"), info.Scope, canonicalRequest)
	signingKey := computeSigningKey(secret, info.Date, info.Region, info.Service)
	info.Signature = fmt.Sprintf("%x", hmacSHA256(signingKey, []byte(stringToSign)))
}

var validCreds = aws.Credentials{
	AccessKeyID:     testAccessKey,
	SecretAccessKey: testSecretKey,
}

func newUnsignedPayloadS3Client(endpoint string) *s3.Client {
	return s3.New(s3.Options{
		Region: testRegion,
		Credentials: credentials.NewStaticCredentialsProvider(
			testAccessKey, testSecretKey, "",
		),
		BaseEndpoint: aws.String(endpoint),
		UsePathStyle: true,
		APIOptions: []func(*middleware.Stack) error{
			awsv4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware,
		},
	})
}

func TestSigV4_RawSigner_GET(t *testing.T) {
	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	req := signedRequest(t, http.MethodGet, ts.URL+"/"+testBucket+"/my-key.txt", nil, unsignedPayload, validCreds)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSigV4_RawSigner_PUT_WithBody(t *testing.T) {
	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	body := []byte("hello world, this is a test upload")

	req := signedRequest(t, http.MethodPut, ts.URL+"/"+testBucket+"/upload/test.txt", body, unsignedPayload, validCreds)
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

func TestSigV4_RawSigner_ConcretePayloadHashRejected(t *testing.T) {
	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	body := []byte("payload with a concrete hash")
	payloadHash := fmt.Sprintf("%x", sha256.Sum256(body))
	req := signedRequest(t, http.MethodPut, ts.URL+"/"+testBucket+"/hashed.bin", body, payloadHash, validCreds)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(respBody), "<Code>InvalidRequest</Code>")
	assert.Contains(t, string(respBody), "UNSIGNED-PAYLOAD")
}

func TestSigV4_RejectsMissingHostCoverageEvenWithMatchingSignature(t *testing.T) {
	signedAt := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	req := signedRequestAtTime(t, http.MethodGet, "https://s3.example.com/test-bucket/key", nil, unsignedPayload, validCreds, signedAt)
	info := parsedAuthInfo(t, req)

	withoutHost := info.SignedHeaders[:0]
	for _, header := range info.SignedHeaders {
		if header != "host" {
			withoutHost = append(withoutHost, header)
		}
	}
	info.SignedHeaders = withoutHost
	recomputeTestSignature(req, info, testSecretKey)

	require.Error(t, verifySignatureAtTime(req, info, testSecretKey, signedAt, time.Minute))
}

func TestSigV4_RejectsCredentialScopeMismatchEvenWithMatchingSignature(t *testing.T) {
	signedAt := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*AuthInfo)
	}{
		{
			name: "scope date",
			mutate: func(info *AuthInfo) {
				info.Date = "20260805"
				info.Scope = "20260805/" + info.Region + "/s3/aws4_request"
			},
		},
		{
			name: "service",
			mutate: func(info *AuthInfo) {
				info.Service = "execute-api"
				info.Scope = info.Date + "/" + info.Region + "/execute-api/aws4_request"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := signedRequestAtTime(t, http.MethodGet, "https://s3.example.com/test-bucket/key", nil, unsignedPayload, validCreds, signedAt)
			info := parsedAuthInfo(t, req)
			tt.mutate(info)
			recomputeTestSignature(req, info, testSecretKey)

			require.Error(t, verifySignatureAtTime(req, info, testSecretKey, signedAt, time.Minute))
		})
	}
}

func TestSigV4_AcceptsAWSCanonicalMultiValueHeaderWhitespace(t *testing.T) {
	signedAt := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	req, err := http.NewRequest(http.MethodGet, "https://s3.example.com/test-bucket/key", nil)
	require.NoError(t, err)
	req.Header.Set("x-amz-content-sha256", unsignedPayload)
	req.Header.Add("X-Test-Values", "  alpha   beta  ")
	req.Header.Add("X-Test-Values", "gamma\t\tdelta")
	require.NoError(t, awsv4.NewSigner().SignHTTP(context.Background(), validCreds, req, unsignedPayload, "s3", testRegion, signedAt))

	info := parsedAuthInfo(t, req)
	require.NoError(t, verifySignatureAtTime(req, info, testSecretKey, signedAt, time.Minute))
}

func TestParseAuthorizationHeaderRejectsNonCanonicalSignedHeaderList(t *testing.T) {
	for _, signedHeaders := range []string{
		"x-amz-date;host",
		"host;x-amz-date;host",
		"Host;x-amz-date",
	} {
		t.Run(signedHeaders, func(t *testing.T) {
			header := "AWS4-HMAC-SHA256 Credential=AKID/20260806/us-east-1/s3/aws4_request, SignedHeaders=" + signedHeaders + ", Signature=" + strings.Repeat("a", 64)
			_, err := parseAuthorizationHeader(header)
			require.Error(t, err)
		})
	}
}

func TestParseAuthorizationHeaderRejectsInvalidCredentialScopeAndSignature(t *testing.T) {
	tests := []struct {
		name       string
		credential string
		signature  string
	}{
		{name: "invalid date", credential: "AKID/not-a-date/us-east-1/s3/aws4_request", signature: strings.Repeat("a", 64)},
		{name: "empty region", credential: "AKID/20260806//s3/aws4_request", signature: strings.Repeat("a", 64)},
		{name: "wrong service", credential: "AKID/20260806/us-east-1/execute-api/aws4_request", signature: strings.Repeat("a", 64)},
		{name: "wrong terminator", credential: "AKID/20260806/us-east-1/s3/not-aws4-request", signature: strings.Repeat("a", 64)},
		{name: "uppercase signature", credential: "AKID/20260806/us-east-1/s3/aws4_request", signature: strings.Repeat("A", 64)},
		{name: "short signature", credential: "AKID/20260806/us-east-1/s3/aws4_request", signature: strings.Repeat("a", 63)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := "AWS4-HMAC-SHA256 Credential=" + tt.credential + ", SignedHeaders=host;x-amz-date, Signature=" + tt.signature
			_, err := parseAuthorizationHeader(header)
			require.Error(t, err)
		})
	}
}

func TestParseAuthorizationHeaderRejectsUnsafeAccessKeyIDs(t *testing.T) {
	for name, accessKeyID := range map[string]string{
		"oversized": strings.Repeat("a", 129),
		"control":   "AKID\nINJECTED",
		"comma":     "AKID,INJECTED",
		"equals":    "AKID=INJECTED",
		"space":     "AKID INJECTED",
	} {
		t.Run(name, func(t *testing.T) {
			header := "AWS4-HMAC-SHA256 Credential=" + accessKeyID + "/20260806/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=" + strings.Repeat("a", 64)
			_, err := parseAuthorizationHeader(header)
			require.Error(t, err)
		})
	}
}

func TestSigV4S3CanonicalPathBindsEscapedWireIdentity(t *testing.T) {
	signedAt := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	for name, target := range map[string]string{
		"encoded slash":   "https://s3.example.com/test-bucket/a%2Fb",
		"literal percent": "https://s3.example.com/test-bucket/a%25b",
		"unicode":         "https://s3.example.com/test-bucket/snowman-\u2603",
	} {
		t.Run(name+" accepted", func(t *testing.T) {
			req := signedRequestAtTime(t, http.MethodGet, target, nil, unsignedPayload, validCreds, signedAt)
			require.NoError(t, verifySignatureAtTime(req, parsedAuthInfo(t, req), testSecretKey, signedAt, time.Minute))
		})
	}

	t.Run("encoded slash cannot become a path separator", func(t *testing.T) {
		req := signedRequestAtTime(t, http.MethodGet, "https://s3.example.com/test-bucket/a%2Fb", nil, unsignedPayload, validCreds, signedAt)
		info := parsedAuthInfo(t, req)
		req.URL.RawPath = ""
		require.Error(t, verifySignatureAtTime(req, info, testSecretKey, signedAt, time.Minute))
	})

	t.Run("percent escape case is signed", func(t *testing.T) {
		req := signedRequestAtTime(t, http.MethodGet, "https://s3.example.com/test-bucket/a%2Fb", nil, unsignedPayload, validCreds, signedAt)
		info := parsedAuthInfo(t, req)
		req.URL.RawPath = strings.Replace(req.URL.RawPath, "%2F", "%2f", 1)
		require.Error(t, verifySignatureAtTime(req, info, testSecretKey, signedAt, time.Minute))
	})

	t.Run("literal percent identity cannot change", func(t *testing.T) {
		req := signedRequestAtTime(t, http.MethodGet, "https://s3.example.com/test-bucket/a%25b", nil, unsignedPayload, validCreds, signedAt)
		info := parsedAuthInfo(t, req)
		changed, err := url.Parse("https://s3.example.com/test-bucket/a%2525b")
		require.NoError(t, err)
		req.URL = changed
		require.Error(t, verifySignatureAtTime(req, info, testSecretKey, signedAt, time.Minute))
	})
}

func TestSigV4_RejectsUnsupportedSessionTokenAndTrailerModes(t *testing.T) {
	signedAt := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		creds   aws.Credentials
		headers map[string]string
	}{
		{
			name:  "session token",
			creds: aws.Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey, SessionToken: "session-token"},
		},
		{
			name:    "signed trailer",
			creds:   validCreds,
			headers: map[string]string{"x-amz-trailer": "x-amz-checksum-crc32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := signedRequestAtTimeWithHeaders(t, http.MethodPut, "https://s3.example.com/test-bucket/key", nil, unsignedPayload, tt.creds, signedAt, tt.headers)
			info := parsedAuthInfo(t, req)
			require.Error(t, verifySignatureAtTime(req, info, testSecretKey, signedAt, time.Minute))
		})
	}
}

func TestSigV4_RejectsStreamingPayloadMode(t *testing.T) {
	signedAt := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	req := signedRequestAtTime(t, http.MethodPut, "https://s3.example.com/test-bucket/key", nil, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", validCreds, signedAt)
	info := parsedAuthInfo(t, req)
	require.ErrorIs(t, verifySignatureAtTime(req, info, testSecretKey, signedAt, time.Minute), errUnsupportedPayloadHash)
}

func TestSigV4_RejectsUnsignedDateAndAlteredHost(t *testing.T) {
	signedAt := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

	t.Run("x-amz-date not signed", func(t *testing.T) {
		req := signedRequestAtTime(t, http.MethodGet, "https://s3.example.com/test-bucket/key", nil, unsignedPayload, validCreds, signedAt)
		info := parsedAuthInfo(t, req)
		filtered := info.SignedHeaders[:0]
		for _, header := range info.SignedHeaders {
			if header != "x-amz-date" {
				filtered = append(filtered, header)
			}
		}
		info.SignedHeaders = filtered
		recomputeTestSignature(req, info, testSecretKey)
		require.Error(t, verifySignatureAtTime(req, info, testSecretKey, signedAt, time.Minute))
	})

	t.Run("host altered after signing", func(t *testing.T) {
		req := signedRequestAtTime(t, http.MethodGet, "https://s3.example.com/test-bucket/key", nil, unsignedPayload, validCreds, signedAt)
		info := parsedAuthInfo(t, req)
		req.Host = "attacker.example.com"
		require.Error(t, verifySignatureAtTime(req, info, testSecretKey, signedAt, time.Minute))
	})
}

func TestSigV4_RejectsDuplicateAuthenticationHeaders(t *testing.T) {
	signedAt := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	for _, header := range []string{"x-amz-date", "x-amz-content-sha256"} {
		t.Run(header, func(t *testing.T) {
			req := signedRequestAtTime(t, http.MethodGet, "https://s3.example.com/test-bucket/key", nil, unsignedPayload, validCreds, signedAt)
			info := parsedAuthInfo(t, req)
			req.Header.Add(header, req.Header.Get(header))
			require.Error(t, verifySignatureAtTime(req, info, testSecretKey, signedAt, time.Minute))
		})
	}
}

func FuzzParseAuthorizationHeader(f *testing.F) {
	f.Add("AWS4-HMAC-SHA256 Credential=AKID/20260806/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=" + strings.Repeat("a", 64))
	f.Add("not-an-authorization-header")
	f.Fuzz(func(t *testing.T, header string) {
		_, _ = parseAuthorizationHeader(header)
	})
}

func TestSigV4_RawSigner_WithQueryParams(t *testing.T) {
	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	req := signedRequest(t, http.MethodGet, ts.URL+"/"+testBucket+"?list-type=2&prefix=photos/&max-keys=100", nil, unsignedPayload, validCreds)

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
	req := signedRequest(t, http.MethodGet, ts.URL+"/"+testBucket+"/secret.txt", nil, unsignedPayload, badCreds)

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
	req := signedRequest(t, http.MethodGet, ts.URL+"/"+testBucket+"/test.txt", nil, unsignedPayload, unknownCreds)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestSigV4_RawSigner_RequestTimeTooSkewed(t *testing.T) {
	oldSkew := env.SigV4MaxClockSkew
	env.SigV4MaxClockSkew = 15 * time.Minute
	t.Cleanup(func() {
		env.SigV4MaxClockSkew = oldSkew
	})

	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	req := signedRequestAtTime(t, http.MethodGet, ts.URL+"/"+testBucket+"/old-object.txt", nil, unsignedPayload, validCreds, time.Now().UTC().Add(-16*time.Minute))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, string(body), "<Code>RequestTimeTooSkewed</Code>")
}

func TestSigV4_RawSigner_ConfigurableClockSkew(t *testing.T) {
	oldSkew := env.SigV4MaxClockSkew
	env.SigV4MaxClockSkew = time.Hour
	t.Cleanup(func() {
		env.SigV4MaxClockSkew = oldSkew
	})

	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	req := signedRequestAtTime(t, http.MethodGet, ts.URL+"/"+testBucket+"/old-but-accepted.txt", nil, unsignedPayload, validCreds, time.Now().UTC().Add(-30*time.Minute))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSigV4_S3Client_PutObject(t *testing.T) {
	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	client := newUnsignedPayloadS3Client(ts.URL)

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
			strings.Contains(errStr, "SignatureDoesNotMatch") || strings.Contains(errStr, "403") || strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "InvalidRequest"),
			"signature verification failed: %v", err,
		)
		t.Logf("non-signature error (signature was accepted): %v", err)
	}
}

func TestSigV4_S3Client_HeadObject(t *testing.T) {
	resolver := newTestResolver()
	ts := newTestServer(t, resolver)

	client := newUnsignedPayloadS3Client(ts.URL)

	_, err := client.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("sdk-test/hello.txt"),
	})
	if err != nil {
		errStr := err.Error()
		assert.False(t,
			strings.Contains(errStr, "SignatureDoesNotMatch") || strings.Contains(errStr, "403") || strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "InvalidRequest"),
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

	payloadHash := unsignedPayload
	req.Header.Set("x-amz-content-sha256", payloadHash)

	signer := awsv4.NewSigner()
	require.NoError(t, signer.SignHTTP(context.Background(), validCreds, req, payloadHash, "s3", testRegion, time.Now()))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
