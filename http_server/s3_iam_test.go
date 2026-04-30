package http_server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/danthegoodman1/vbuckets/iam"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapS3IAMChecks_CoreOperations(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		target    string
		bucket    string
		objectKey string
		headers   map[string]string
		want      []iam.Request
	}{
		{
			name:   "list all my buckets",
			method: http.MethodGet,
			target: "/",
			bucket: "",
			want:   []iam.Request{{Action: "s3:ListAllMyBuckets", Resource: "*"}},
		},
		{
			name:   "create bucket",
			method: http.MethodPut,
			target: "/test-bucket",
			want:   []iam.Request{{Action: "s3:CreateBucket", Resource: "arn:aws:s3:::test-bucket"}},
		},
		{
			name:   "list bucket",
			method: http.MethodGet,
			target: "/test-bucket?list-type=2&prefix=dir/",
			want:   []iam.Request{{Action: "s3:ListBucket", Resource: "arn:aws:s3:::test-bucket"}},
		},
		{
			name:      "get object",
			method:    http.MethodGet,
			target:    "/test-bucket/a.txt",
			objectKey: "a.txt",
			want:      []iam.Request{{Action: "s3:GetObject", Resource: "arn:aws:s3:::test-bucket/a.txt"}},
		},
		{
			name:      "head object version",
			method:    http.MethodHead,
			target:    "/test-bucket/a.txt?versionId=version-1",
			objectKey: "a.txt",
			want:      []iam.Request{{Action: "s3:GetObjectVersion", Resource: "arn:aws:s3:::test-bucket/a.txt"}},
		},
		{
			name:      "put object with acl and tagging headers",
			method:    http.MethodPut,
			target:    "/test-bucket/a.txt",
			objectKey: "a.txt",
			headers: map[string]string{
				"x-amz-acl":     "public-read",
				"x-amz-tagging": "class=public",
			},
			want: []iam.Request{
				{Action: "s3:PutObject", Resource: "arn:aws:s3:::test-bucket/a.txt"},
				{Action: "s3:PutObjectAcl", Resource: "arn:aws:s3:::test-bucket/a.txt"},
				{Action: "s3:PutObjectTagging", Resource: "arn:aws:s3:::test-bucket/a.txt"},
			},
		},
		{
			name:      "copy object same bucket",
			method:    http.MethodPut,
			target:    "/test-bucket/copied.txt",
			objectKey: "copied.txt",
			headers: map[string]string{
				"x-amz-copy-source": "/test-bucket/source.txt",
			},
			want: []iam.Request{
				{Action: "s3:PutObject", Resource: "arn:aws:s3:::test-bucket/copied.txt"},
				{Action: "s3:GetObject", Resource: "arn:aws:s3:::test-bucket/source.txt"},
			},
		},
		{
			name:      "copy object source version",
			method:    http.MethodPut,
			target:    "/test-bucket/copied.txt",
			objectKey: "copied.txt",
			headers: map[string]string{
				"x-amz-copy-source": "/test-bucket/source.txt?versionId=version-1",
			},
			want: []iam.Request{
				{Action: "s3:PutObject", Resource: "arn:aws:s3:::test-bucket/copied.txt"},
				{Action: "s3:GetObjectVersion", Resource: "arn:aws:s3:::test-bucket/source.txt"},
			},
		},
		{
			name:      "copy object with acl and tagging headers",
			method:    http.MethodPut,
			target:    "/test-bucket/copied.txt",
			objectKey: "copied.txt",
			headers: map[string]string{
				"x-amz-copy-source": "/test-bucket/source.txt",
				"x-amz-acl":         "public-read",
				"x-amz-tagging":     "class=public",
			},
			want: []iam.Request{
				{Action: "s3:PutObject", Resource: "arn:aws:s3:::test-bucket/copied.txt"},
				{Action: "s3:GetObject", Resource: "arn:aws:s3:::test-bucket/source.txt"},
				{Action: "s3:PutObjectAcl", Resource: "arn:aws:s3:::test-bucket/copied.txt"},
				{Action: "s3:PutObjectTagging", Resource: "arn:aws:s3:::test-bucket/copied.txt"},
			},
		},
		{
			name:      "put object tagging subresource",
			method:    http.MethodPut,
			target:    "/test-bucket/a.txt?tagging",
			objectKey: "a.txt",
			want:      []iam.Request{{Action: "s3:PutObjectTagging", Resource: "arn:aws:s3:::test-bucket/a.txt"}},
		},
		{
			name:      "delete object version",
			method:    http.MethodDelete,
			target:    "/test-bucket/a.txt?versionId=version-1",
			objectKey: "a.txt",
			want:      []iam.Request{{Action: "s3:DeleteObjectVersion", Resource: "arn:aws:s3:::test-bucket/a.txt"}},
		},
		{
			name:      "abort multipart upload",
			method:    http.MethodDelete,
			target:    "/test-bucket/a.txt?uploadId=upload-1",
			objectKey: "a.txt",
			want:      []iam.Request{{Action: "s3:AbortMultipartUpload", Resource: "arn:aws:s3:::test-bucket/a.txt"}},
		},
		{
			name:      "list multipart parts",
			method:    http.MethodGet,
			target:    "/test-bucket/a.txt?uploadId=upload-1",
			objectKey: "a.txt",
			want:      []iam.Request{{Action: "s3:ListMultipartUploadParts", Resource: "arn:aws:s3:::test-bucket/a.txt"}},
		},
		{
			name:   "list bucket multipart uploads",
			method: http.MethodGet,
			target: "/test-bucket?uploads&prefix=dir/",
			want:   []iam.Request{{Action: "s3:ListBucketMultipartUploads", Resource: "arn:aws:s3:::test-bucket"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			bucket := tt.bucket
			if bucket == "" && tt.name != "list all my buckets" {
				bucket = testBucket
			}
			got, err := mapS3IAMChecks(req, bucket, tt.objectKey)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMapS3IAMChecks_RejectsUnsupportedOperations(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		target    string
		objectKey string
		headers   map[string]string
	}{
		{name: "bucket versions", method: http.MethodGet, target: "/test-bucket?versions"},
		{name: "object acl read", method: http.MethodGet, target: "/test-bucket/a.txt?acl", objectKey: "a.txt"},
		{
			name:      "copy object cross bucket",
			method:    http.MethodPut,
			target:    "/test-bucket/a.txt",
			objectKey: "a.txt",
			headers: map[string]string{
				"x-amz-copy-source": "/source-bucket/source.txt",
			},
		},
		{
			name:      "multipart copy object",
			method:    http.MethodPut,
			target:    "/test-bucket/a.txt?partNumber=1&uploadId=upload-1",
			objectKey: "a.txt",
			headers: map[string]string{
				"x-amz-copy-source": "/test-bucket/source.txt",
			},
		},
		{
			name:      "copy object acl subresource",
			method:    http.MethodPut,
			target:    "/test-bucket/a.txt?acl",
			objectKey: "a.txt",
			headers: map[string]string{
				"x-amz-copy-source": "/test-bucket/source.txt",
			},
		},
		{
			name:      "copy object tagging subresource",
			method:    http.MethodPut,
			target:    "/test-bucket/a.txt?tagging",
			objectKey: "a.txt",
			headers: map[string]string{
				"x-amz-copy-source": "/test-bucket/source.txt",
			},
		},
		{name: "multi object delete", method: http.MethodPost, target: "/test-bucket?delete"},
		{name: "delete with unknown query", method: http.MethodDelete, target: "/test-bucket/a.txt?policy", objectKey: "a.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			_, err := mapS3IAMChecks(req, testBucket, tt.objectKey)
			require.ErrorIs(t, err, ErrUnsupportedS3Operation)
		})
	}
}

func TestBuildS3IAMRequests_Context(t *testing.T) {
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	req := httptest.NewRequest(http.MethodGet, "/test-bucket?list-type=2&delimiter=/&max-keys=25", nil)
	req.Header.Set("X-Amz-Date", now.Add(-2*time.Second).Format("20060102T150405Z"))
	req.Header.Set("x-amz-acl", "private")

	checks, err := buildS3IAMRequests(req, testBucket, "", "", &AuthInfo{}, now)
	require.NoError(t, err)
	require.Len(t, checks, 1)

	ctx := checks[0].Context
	assert.Equal(t, []string{""}, ctx["s3:prefix"])
	assert.Equal(t, []string{"/"}, ctx["s3:delimiter"])
	assert.Equal(t, []string{"25"}, ctx["s3:max-keys"])
	assert.Equal(t, []string{"private"}, ctx["s3:x-amz-acl"])
	assert.Equal(t, []string{"REST-HEADER"}, ctx["s3:authtype"])
	assert.Equal(t, []string{"AWS4-HMAC-SHA256"}, ctx["s3:signatureversion"])
	assert.Equal(t, []string{"2000"}, ctx["s3:signatureage"])
	assert.Equal(t, []string{"false"}, ctx["aws:securetransport"])
	assert.Equal(t, []string{now.Format(time.RFC3339)}, ctx["aws:currenttime"])
	assert.Equal(t, []string{fmt.Sprintf("%d", now.Unix())}, ctx["aws:epochtime"])
}

func TestBuildS3IAMRequests_ListBucketsDoesNotSetListObjectConditions(t *testing.T) {
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	req := httptest.NewRequest(http.MethodGet, "/?x-id=ListBuckets", nil)

	checks, err := buildS3IAMRequests(req, "", "", "", &AuthInfo{}, now)
	require.NoError(t, err)
	require.Len(t, checks, 1)

	assert.Equal(t, "s3:ListAllMyBuckets", checks[0].Action)
	assert.NotContains(t, checks[0].Context, "s3:prefix")
	assert.NotContains(t, checks[0].Context, "s3:delimiter")
	assert.NotContains(t, checks[0].Context, "s3:max-keys")
}

func TestBuildS3IAMRequests_CreateBucketLocationConstraintContext(t *testing.T) {
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	req := httptest.NewRequest(http.MethodPut, "/test-bucket", nil)

	checks, err := buildS3IAMRequests(req, testBucket, "", "us-west-2", &AuthInfo{}, now)
	require.NoError(t, err)
	require.Len(t, checks, 1)
	assert.Equal(t, "s3:CreateBucket", checks[0].Action)
	assert.Equal(t, []string{"us-west-2"}, checks[0].Context["s3:locationconstraint"])

	policy := mustParseTestPolicy(`{
		"Statement": {
			"Effect": "Allow",
			"Action": "s3:CreateBucket",
			"Resource": "arn:aws:s3:::test-bucket",
			"Condition": {"StringEquals": {"s3:LocationConstraint": "us-west-2"}}
		}
	}`)
	require.NoError(t, policy.Authorize(checks[0]))
}

func TestParseCreateBucketLocationConstraintRejectsUnexpectedRoot(t *testing.T) {
	location, err := parseCreateBucketLocationConstraint(io.NopCloser(strings.NewReader(`<NotCreateBucketConfiguration><LocationConstraint>us-west-2</LocationConstraint></NotCreateBucketConfiguration>`)))
	require.Error(t, err)
	assert.Empty(t, location)
}

func TestFormatS3CreationDateUsesEpochForZeroValue(t *testing.T) {
	assert.Equal(t, "1970-01-01T00:00:00Z", formatS3CreationDate(time.Time{}))
}

func TestS3Auth_IAMDenyDoesNotCallHandler(t *testing.T) {
	resolver := newTestResolver()
	resolver.credentials = func(_ context.Context, accessKeyID string) (*VirtualCredentials, error) {
		if accessKeyID != testAccessKey {
			return nil, fmt.Errorf("unknown access key ID: %s", accessKeyID)
		}
		return &VirtualCredentials{
			SecretKey: testSecretKey,
			IAMPolicy: mustParseTestPolicy(`{
				"Statement": {
					"Effect": "Allow",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::test-bucket/allowed/*"
				}
			}`),
		}, nil
	}

	var called bool
	handler := S3Auth(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req := signedRequest(t, http.MethodPut, ts.URL+"/"+testBucket+"/allowed/a.txt", nil, unsignedPayload, validCreds)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, string(body), "<Code>AccessDenied</Code>")
	assert.False(t, called)
}

func TestS3Auth_CopyObjectAllowedSameBucketCallsHandler(t *testing.T) {
	resolver := newTestResolver()
	resolver.credentials = func(_ context.Context, accessKeyID string) (*VirtualCredentials, error) {
		if accessKeyID != testAccessKey {
			return nil, fmt.Errorf("unknown access key ID: %s", accessKeyID)
		}
		return &VirtualCredentials{
			SecretKey: testSecretKey,
			IAMPolicy: mustParseTestPolicy(`{
				"Statement": [
					{
						"Effect": "Allow",
						"Action": "s3:PutObject",
						"Resource": "arn:aws:s3:::test-bucket/copied.txt"
					},
					{
						"Effect": "Allow",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::test-bucket/source.txt"
					}
				]
			}`),
		}, nil
	}

	var called bool
	handler := S3Auth(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		assert.Equal(t, "copied.txt", getObjectKey(r.Context()))
		assert.Equal(t, "/"+testBucket+"/source.txt", r.Header.Get(copySourceHeader))
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req := signedRequestWithHeaders(t, http.MethodPut, ts.URL+"/"+testBucket+"/copied.txt", nil, unsignedPayload, validCreds, map[string]string{
		copySourceHeader: "/" + testBucket + "/source.txt",
	})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, called)
}

func TestS3Auth_CopyObjectUnsignedCopySourceDoesNotCallHandler(t *testing.T) {
	resolver := newTestResolver()

	var called bool
	handler := S3Auth(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req := signedRequest(t, http.MethodPut, ts.URL+"/"+testBucket+"/copied.txt", nil, unsignedPayload, validCreds)
	req.Header.Set(copySourceHeader, "/"+testBucket+"/source.txt")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, string(body), "<Code>AccessDenied</Code>")
	assert.Contains(t, string(body), "not signed")
	assert.False(t, called)
}

func TestS3Auth_CopyObjectMissingSourcePermissionDoesNotCallHandler(t *testing.T) {
	resolver := newTestResolver()
	resolver.credentials = func(_ context.Context, accessKeyID string) (*VirtualCredentials, error) {
		if accessKeyID != testAccessKey {
			return nil, fmt.Errorf("unknown access key ID: %s", accessKeyID)
		}
		return &VirtualCredentials{
			SecretKey: testSecretKey,
			IAMPolicy: mustParseTestPolicy(`{
				"Statement": {
					"Effect": "Allow",
					"Action": "s3:PutObject",
					"Resource": "arn:aws:s3:::test-bucket/copied.txt"
				}
			}`),
		}, nil
	}

	var called bool
	handler := S3Auth(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req := signedRequestWithHeaders(t, http.MethodPut, ts.URL+"/"+testBucket+"/copied.txt", nil, unsignedPayload, validCreds, map[string]string{
		copySourceHeader: "/" + testBucket + "/source.txt",
	})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, string(body), "<Code>AccessDenied</Code>")
	assert.False(t, called)
}

func TestS3Auth_CopyObjectMissingDestinationPermissionDoesNotCallHandler(t *testing.T) {
	resolver := newTestResolver()
	resolver.credentials = func(_ context.Context, accessKeyID string) (*VirtualCredentials, error) {
		if accessKeyID != testAccessKey {
			return nil, fmt.Errorf("unknown access key ID: %s", accessKeyID)
		}
		return &VirtualCredentials{
			SecretKey: testSecretKey,
			IAMPolicy: mustParseTestPolicy(`{
				"Statement": {
					"Effect": "Allow",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::test-bucket/source.txt"
				}
			}`),
		}, nil
	}

	var called bool
	handler := S3Auth(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req := signedRequestWithHeaders(t, http.MethodPut, ts.URL+"/"+testBucket+"/copied.txt", nil, unsignedPayload, validCreds, map[string]string{
		copySourceHeader: "/" + testBucket + "/source.txt",
	})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, string(body), "<Code>AccessDenied</Code>")
	assert.False(t, called)
}

func TestS3Auth_CopyObjectACLAndTaggingPermissionsRequired(t *testing.T) {
	resolver := newTestResolver()
	resolver.credentials = func(_ context.Context, accessKeyID string) (*VirtualCredentials, error) {
		if accessKeyID != testAccessKey {
			return nil, fmt.Errorf("unknown access key ID: %s", accessKeyID)
		}
		return &VirtualCredentials{
			SecretKey: testSecretKey,
			IAMPolicy: mustParseTestPolicy(`{
				"Statement": [
					{
						"Effect": "Allow",
						"Action": "s3:PutObject",
						"Resource": "arn:aws:s3:::test-bucket/copied.txt"
					},
					{
						"Effect": "Allow",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::test-bucket/source.txt"
					}
				]
			}`),
		}, nil
	}

	var called bool
	handler := S3Auth(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req := signedRequestWithHeaders(t, http.MethodPut, ts.URL+"/"+testBucket+"/copied.txt", nil, unsignedPayload, validCreds, map[string]string{
		copySourceHeader: "/" + testBucket + "/source.txt",
		"x-amz-acl":      "public-read",
		"x-amz-tagging":  "class=public",
	})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, string(body), "<Code>AccessDenied</Code>")
	assert.False(t, called)
}

func TestS3Auth_CopyObjectVersionRequiresGetObjectVersion(t *testing.T) {
	resolver := newTestResolver()
	resolver.credentials = func(_ context.Context, accessKeyID string) (*VirtualCredentials, error) {
		if accessKeyID != testAccessKey {
			return nil, fmt.Errorf("unknown access key ID: %s", accessKeyID)
		}
		return &VirtualCredentials{
			SecretKey: testSecretKey,
			IAMPolicy: mustParseTestPolicy(`{
				"Statement": [
					{
						"Effect": "Allow",
						"Action": "s3:PutObject",
						"Resource": "arn:aws:s3:::test-bucket/copied.txt"
					},
					{
						"Effect": "Allow",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::test-bucket/source.txt"
					}
				]
			}`),
		}, nil
	}

	var called bool
	handler := S3Auth(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req := signedRequestWithHeaders(t, http.MethodPut, ts.URL+"/"+testBucket+"/copied.txt", nil, unsignedPayload, validCreds, map[string]string{
		copySourceHeader: "/" + testBucket + "/source.txt?versionId=version-1",
	})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, string(body), "<Code>AccessDenied</Code>")
	assert.False(t, called)
}

func TestS3Auth_CopyObjectUnsupportedFormsDoNotCallHandler(t *testing.T) {
	resolver := newTestResolver()

	tests := []struct {
		name       string
		target     string
		copySource string
	}{
		{
			name:       "cross bucket",
			target:     "/" + testBucket + "/copied.txt",
			copySource: "/other-bucket/source.txt",
		},
		{
			name:       "multipart copy",
			target:     "/" + testBucket + "/copied.txt?partNumber=1&uploadId=upload-1",
			copySource: "/" + testBucket + "/source.txt",
		},
		{
			name:       "acl subresource",
			target:     "/" + testBucket + "/copied.txt?acl",
			copySource: "/" + testBucket + "/source.txt",
		},
		{
			name:       "tagging subresource",
			target:     "/" + testBucket + "/copied.txt?tagging",
			copySource: "/" + testBucket + "/source.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var called bool
			handler := S3Auth(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))
			ts := httptest.NewServer(handler)
			t.Cleanup(ts.Close)

			req := signedRequestWithHeaders(t, http.MethodPut, ts.URL+tt.target, nil, unsignedPayload, validCreds, map[string]string{
				copySourceHeader: tt.copySource,
			})

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			assert.Contains(t, string(body), "<Code>AccessDenied</Code>")
			assert.False(t, called)
		})
	}
}

func TestS3Client_CopyObjectAllowedSameBucketCallsHandler(t *testing.T) {
	resolver := newTestResolver()

	var called bool
	handler := S3Auth(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<CopyObjectResult><ETag>"abc123"</ETag></CopyObjectResult>`))
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	client := newUnsignedPayloadS3Client(ts.URL)
	_, err := client.CopyObject(context.Background(), &s3.CopyObjectInput{
		Bucket:     aws.String(testBucket),
		Key:        aws.String("copied.txt"),
		CopySource: aws.String(testBucket + "/source.txt"),
	})
	require.NoError(t, err)
	assert.True(t, called)
}

func TestS3Auth_InvalidCredentialPolicyReturnsAccessDenied(t *testing.T) {
	resolver := newTestResolver()
	resolver.credentials = func(_ context.Context, accessKeyID string) (*VirtualCredentials, error) {
		return nil, fmt.Errorf("%w: cached policy is invalid", iam.ErrInvalidPolicy)
	}

	ts := newTestServer(t, resolver)
	req := signedRequest(t, http.MethodGet, ts.URL+"/"+testBucket+"/a.txt", nil, unsignedPayload, validCreds)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, string(body), "<Code>AccessDenied</Code>")
	assert.NotContains(t, string(body), "InvalidAccessKeyId")
}

func TestS3Auth_UnknownAccessKeyStillReturnsInvalidAccessKey(t *testing.T) {
	resolver := newTestResolver()
	resolver.credentials = func(_ context.Context, accessKeyID string) (*VirtualCredentials, error) {
		return nil, errors.New("unknown access key")
	}

	ts := newTestServer(t, resolver)
	req := signedRequest(t, http.MethodGet, ts.URL+"/"+testBucket+"/a.txt", nil, unsignedPayload, validCreds)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, string(body), "<Code>InvalidAccessKeyId</Code>")
}

func TestS3Auth_ListBucketsInterceptsWithoutVBucketLookup(t *testing.T) {
	resolver := newTestResolver()
	var vbucketLookupCalled bool
	resolver.vbucket = func(_ context.Context, accessKeyID, bucketName string) (*VBucketConfig, error) {
		vbucketLookupCalled = true
		return nil, errors.New("should not lookup vbucket")
	}
	resolver.list = func(_ context.Context, accessKeyID string) ([]ListedVBucket, error) {
		require.Equal(t, testAccessKey, accessKeyID)
		return []ListedVBucket{{
			Name:         "alpha",
			CreationDate: time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC),
		}}, nil
	}

	handler := S3Auth(resolver)(handleS3Request(resolver))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req := signedRequest(t, http.MethodGet, ts.URL+"/", nil, unsignedPayload, validCreds)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "<ListAllMyBucketsResult")
	assert.Contains(t, string(body), "<Name>alpha</Name>")
	assert.False(t, vbucketLookupCalled)
}

func TestS3Auth_CreateBucketInterceptsWithoutVBucketLookup(t *testing.T) {
	resolver := newTestResolver()
	var vbucketLookupCalled bool
	var gotBucket, gotLocation string
	resolver.vbucket = func(_ context.Context, accessKeyID, bucketName string) (*VBucketConfig, error) {
		vbucketLookupCalled = true
		return nil, errors.New("should not lookup vbucket")
	}
	resolver.create = func(_ context.Context, accessKeyID, bucketName, locationConstraint string) (*VBucketConfig, error) {
		require.Equal(t, testAccessKey, accessKeyID)
		gotBucket = bucketName
		gotLocation = locationConstraint
		return &VBucketConfig{}, nil
	}

	handler := S3Auth(resolver)(handleS3Request(resolver))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	body := []byte(`<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>us-west-2</LocationConstraint></CreateBucketConfiguration>`)
	req := signedRequest(t, http.MethodPut, ts.URL+"/new-bucket", body, unsignedPayload, validCreds)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "/new-bucket", resp.Header.Get("Location"))
	assert.Contains(t, string(respBody), "<CreateBucketResult")
	assert.Equal(t, "new-bucket", gotBucket)
	assert.Equal(t, "us-west-2", gotLocation)
	assert.False(t, vbucketLookupCalled)
}

func TestS3Auth_CreateBucketDeniedDoesNotMutate(t *testing.T) {
	resolver := newTestResolver()
	resolver.credentials = func(_ context.Context, accessKeyID string) (*VirtualCredentials, error) {
		return &VirtualCredentials{
			SecretKey: testSecretKey,
			IAMPolicy: mustParseTestPolicy(`{
				"Statement": {
					"Effect": "Allow",
					"Action": "s3:ListAllMyBuckets",
					"Resource": "*"
				}
			}`),
		}, nil
	}
	var createCalled bool
	resolver.create = func(_ context.Context, accessKeyID, bucketName, locationConstraint string) (*VBucketConfig, error) {
		createCalled = true
		return &VBucketConfig{}, nil
	}

	handler := S3Auth(resolver)(handleS3Request(resolver))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req := signedRequest(t, http.MethodPut, ts.URL+"/new-bucket", nil, unsignedPayload, validCreds)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.False(t, createCalled)
}

func TestS3Client_CreateBucketAndListBuckets(t *testing.T) {
	resolver := newTestResolver()
	created := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	var buckets []ListedVBucket
	resolver.create = func(_ context.Context, accessKeyID, bucketName, locationConstraint string) (*VBucketConfig, error) {
		buckets = append(buckets, ListedVBucket{Name: bucketName, CreationDate: created})
		return &VBucketConfig{}, nil
	}
	resolver.list = func(_ context.Context, accessKeyID string) ([]ListedVBucket, error) {
		return buckets, nil
	}

	router := chi.NewRouter()
	RegisterS3Routes(resolver)(router)
	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)

	client := newUnsignedPayloadS3Client(ts.URL)

	_, err := client.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket: aws.String("sdk-created-bucket"),
	})
	require.NoError(t, err)

	listResult, err := client.ListBuckets(context.Background(), &s3.ListBucketsInput{})
	require.NoError(t, err)
	require.Len(t, listResult.Buckets, 1)
	assert.Equal(t, "sdk-created-bucket", *listResult.Buckets[0].Name)
	assert.True(t, strings.HasPrefix(listResult.Buckets[0].CreationDate.Format(time.RFC3339), "2026-04-25T12:00:00Z"))
}
