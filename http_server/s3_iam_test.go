package http_server

import (
	"bytes"
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

func mapS3IAMChecks(r *http.Request, bucket, objectKey string) ([]iam.Request, error) {
	plan, err := planS3Operation(r, bucket, objectKey)
	if err != nil {
		return nil, err
	}
	checks := buildS3IAMRequestsFromPlan(plan)
	for i := range checks {
		checks[i].Context = nil
	}
	return checks, nil
}

func buildS3IAMRequests(r *http.Request, bucket, objectKey, locationConstraint string, now time.Time) ([]iam.Request, error) {
	plan, err := planS3Operation(r, bucket, objectKey)
	if err != nil {
		return nil, err
	}
	plan = plan.withAuthorizationContext(locationConstraint, now)
	return buildS3IAMRequestsFromPlan(plan), nil
}

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

func TestMapS3IAMChecks_FailsClosedOnAmbiguousQueryShapes(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		target    string
		bucket    string
		objectKey string
		headers   map[string]string
	}{
		{name: "put object retention", method: http.MethodPut, target: "/test-bucket/a.txt?retention", bucket: testBucket, objectKey: "a.txt"},
		{name: "unknown bucket get", method: http.MethodGet, target: "/test-bucket?inventory", bucket: testBucket},
		{name: "duplicate version id", method: http.MethodGet, target: "/test-bucket/a.txt?versionId=v1&versionId=v2", bucket: testBucket, objectKey: "a.txt"},
		{name: "mismatched x-id", method: http.MethodGet, target: "/test-bucket/a.txt?x-id=PutObject", bucket: testBucket, objectKey: "a.txt"},
		{name: "invalid empty x-id", method: http.MethodGet, target: "/test-bucket/a.txt?x-id=", bucket: testBucket, objectKey: "a.txt"},
		{name: "conflicting object subresources", method: http.MethodPut, target: "/test-bucket/a.txt?acl&tagging", bucket: testBucket, objectKey: "a.txt"},
		{name: "conflicting bucket subresources", method: http.MethodGet, target: "/test-bucket?uploads&list-type=2", bucket: testBucket},
		{name: "duplicate multipart flag", method: http.MethodPost, target: "/test-bucket/a.txt?uploads&uploads", bucket: testBucket, objectKey: "a.txt"},
		{name: "invalid part number", method: http.MethodGet, target: "/test-bucket/a.txt?partNumber=0", bucket: testBucket, objectKey: "a.txt"},
		{name: "invalid max keys", method: http.MethodGet, target: "/test-bucket?max-keys=lots", bucket: testBucket},
		{name: "zero max uploads", method: http.MethodGet, target: "/test-bucket?uploads&max-uploads=0", bucket: testBucket},
		{name: "invalid fetch owner", method: http.MethodGet, target: "/test-bucket?list-type=2&fetch-owner=yes", bucket: testBucket},
		{name: "invalid encoding type", method: http.MethodGet, target: "/test-bucket?encoding-type=xml", bucket: testBucket},
		{name: "object lock header", method: http.MethodPut, target: "/test-bucket/a.txt", bucket: testBucket, objectKey: "a.txt", headers: map[string]string{"x-amz-object-lock-mode": "GOVERNANCE"}},
		{name: "KMS encryption mode", method: http.MethodPut, target: "/test-bucket/a.txt", bucket: testBucket, objectKey: "a.txt", headers: map[string]string{"x-amz-server-side-encryption": "aws:kms"}},
		{name: "copy source on get", method: http.MethodGet, target: "/test-bucket/a.txt", bucket: testBucket, objectKey: "a.txt", headers: map[string]string{copySourceHeader: "/test-bucket/source.txt"}},
		{name: "governance bypass delete", method: http.MethodDelete, target: "/test-bucket/a.txt", bucket: testBucket, objectKey: "a.txt", headers: map[string]string{"x-amz-bypass-governance-retention": "true"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, nil)
			for name, value := range tt.headers {
				req.Header.Set(name, value)
			}
			_, err := mapS3IAMChecks(req, tt.bucket, tt.objectKey)
			require.ErrorIs(t, err, ErrUnsupportedS3Operation)
		})
	}
}

func TestS3Auth_UnsupportedShapeFailsBeforeVBucketLookup(t *testing.T) {
	resolver := newTestResolver()
	vbucketLookups := 0
	resolver.vbucket = func(context.Context, string, string) (*VBucketConfig, error) {
		vbucketLookups++
		return &VBucketConfig{}, nil
	}

	called := false
	handler := S3Auth(resolver)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req := signedRequest(t, http.MethodPut, ts.URL+"/"+testBucket+"/a.txt?retention", nil, unsignedPayload, validCreds)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Zero(t, vbucketLookups)
	assert.False(t, called)
}

func TestPlanS3OperationRejectsBodiesForEmptyOperations(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		target    string
		bucket    string
		objectKey string
		headers   map[string]string
	}{
		{name: "list buckets", method: http.MethodGet, target: "/"},
		{name: "head bucket", method: http.MethodHead, target: "/bucket", bucket: "bucket"},
		{name: "list objects", method: http.MethodGet, target: "/bucket?list-type=2", bucket: "bucket"},
		{name: "list multipart uploads", method: http.MethodGet, target: "/bucket?uploads", bucket: "bucket"},
		{name: "get object", method: http.MethodGet, target: "/bucket/key", bucket: "bucket", objectKey: "key"},
		{name: "head object", method: http.MethodHead, target: "/bucket/key", bucket: "bucket", objectKey: "key"},
		{name: "copy object", method: http.MethodPut, target: "/bucket/key", bucket: "bucket", objectKey: "key", headers: map[string]string{copySourceHeader: "/bucket/source"}},
		{name: "delete object", method: http.MethodDelete, target: "/bucket/key", bucket: "bucket", objectKey: "key"},
		{name: "create multipart", method: http.MethodPost, target: "/bucket/key?uploads", bucket: "bucket", objectKey: "key"},
		{name: "list parts", method: http.MethodGet, target: "/bucket/key?uploadId=u1", bucket: "bucket", objectKey: "key"},
		{name: "abort multipart", method: http.MethodDelete, target: "/bucket/key?uploadId=u1", bucket: "bucket", objectKey: "key"},
	}

	for _, tt := range tests {
		for _, body := range []struct {
			name    string
			unknown bool
		}{
			{name: "known length"},
			{name: "chunked unknown length", unknown: true},
		} {
			t.Run(tt.name+"/"+body.name, func(t *testing.T) {
				req := httptest.NewRequest(tt.method, tt.target, strings.NewReader("not-empty"))
				if body.unknown {
					req.ContentLength = -1
					req.TransferEncoding = []string{"chunked"}
				}
				for name, value := range tt.headers {
					req.Header.Set(name, value)
				}
				_, err := planS3Operation(req, tt.bucket, tt.objectKey)
				require.ErrorIs(t, err, ErrUnsupportedS3Operation)
			})
		}
	}
}

func TestS3AuthRejectsUnboundedOrMalformedCompleteMultipartXML(t *testing.T) {
	resolver := newTestResolver()
	called := false
	handler := S3Auth(resolver)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	tests := []struct {
		name string
		body []byte
	}{
		{name: "oversized", body: bytes.Repeat([]byte("x"), (1<<20)+1)},
		{name: "wrong root", body: []byte(`<NotCompleteMultipartUpload/>`)},
		{name: "malformed", body: []byte(`<CompleteMultipartUpload>`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			req := signedRequest(t, http.MethodPost, ts.URL+"/"+testBucket+"/key?uploadId=u1", tt.body, unsignedPayload, validCreds)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.False(t, called)
		})
	}
}

func TestPlanS3OperationRejectsSingletonAndHeaderConflicts(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		target  string
		headers http.Header
	}{
		{name: "duplicate metadata directive", method: http.MethodPut, target: "/bucket/key", headers: http.Header{copySourceHeader: {"/bucket/source"}, "X-Amz-Metadata-Directive": {"COPY", "REPLACE"}}},
		{name: "duplicate tagging directive", method: http.MethodPut, target: "/bucket/key", headers: http.Header{copySourceHeader: {"/bucket/source"}, "X-Amz-Tagging-Directive": {"COPY", "REPLACE"}}},
		{name: "canned ACL and grant", method: http.MethodPut, target: "/bucket/key", headers: http.Header{"X-Amz-Acl": {"private"}, "X-Amz-Grant-Read": {`id="reader"`}}},
		{name: "AES256 and SSE-C", method: http.MethodPut, target: "/bucket/key", headers: http.Header{"X-Amz-Server-Side-Encryption": {"AES256"}, "X-Amz-Server-Side-Encryption-Customer-Algorithm": {"AES256"}, "X-Amz-Server-Side-Encryption-Customer-Key": {"key"}, "X-Amz-Server-Side-Encryption-Customer-Key-Md5": {"md5"}}},
		{name: "incomplete SSE-C", method: http.MethodPut, target: "/bucket/key", headers: http.Header{"X-Amz-Server-Side-Encryption-Customer-Algorithm": {"AES256"}}},
		{name: "invalid SSE-C algorithm", method: http.MethodPut, target: "/bucket/key", headers: http.Header{"X-Amz-Server-Side-Encryption-Customer-Algorithm": {"DES"}, "X-Amz-Server-Side-Encryption-Customer-Key": {"key"}, "X-Amz-Server-Side-Encryption-Customer-Key-Md5": {"md5"}}},
		{name: "two checksum value families", method: http.MethodPut, target: "/bucket/key", headers: http.Header{"X-Amz-Checksum-Crc32": {"one"}, "X-Amz-Checksum-Sha256": {"two"}}},
		{name: "checksum algorithm mismatch", method: http.MethodPut, target: "/bucket/key", headers: http.Header{"X-Amz-Sdk-Checksum-Algorithm": {"CRC32"}, "X-Amz-Checksum-Sha256": {"sum"}}},
		{name: "duplicate checksum algorithm", method: http.MethodPut, target: "/bucket/key", headers: http.Header{"X-Amz-Sdk-Checksum-Algorithm": {"CRC32", "SHA256"}}},
		{name: "checksum algorithm without value", method: http.MethodPut, target: "/bucket/key", headers: http.Header{"X-Amz-Sdk-Checksum-Algorithm": {"CRC32"}}},
		{name: "unknown checksum family", method: http.MethodPut, target: "/bucket/key", headers: http.Header{"X-Amz-Checksum-Future": {"sum"}}},
		{name: "unknown grant family", method: http.MethodPut, target: "/bucket/key", headers: http.Header{"X-Amz-Grant-Future": {`id="reader"`}}},
		{name: "invalid metadata directive", method: http.MethodPut, target: "/bucket/key", headers: http.Header{"X-Amz-Copy-Source": {"/bucket/source"}, "X-Amz-Metadata-Directive": {"MAYBE"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, nil)
			req.Header = tt.headers.Clone()
			_, err := planS3Operation(req, "bucket", "key")
			require.ErrorIs(t, err, ErrUnsupportedS3Operation)
		})
	}
}

func TestAuthorizeS3PlanUsesValuesCapturedAtPlanning(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	req := httptest.NewRequest(http.MethodGet, "/bucket?list-type=2&prefix=accepted/", nil)
	req.Header.Set("X-Amz-Date", now.Add(-time.Second).Format("20060102T150405Z"))
	plan, err := planS3Operation(req, "bucket", "")
	require.NoError(t, err)

	policy := mustParseTestPolicy(`{
		"Statement": {
			"Effect": "Allow",
			"Action": "s3:ListBucket",
			"Resource": "arn:aws:s3:::bucket",
			"Condition": {"StringEquals": {"s3:prefix": "accepted/"}}
		}
	}`)
	req.URL.RawQuery = "list-type=2&prefix=mutated/"
	req.Header.Set("X-Amz-Date", now.Add(-time.Hour).Format("20060102T150405Z"))

	plan = plan.withAuthorizationContext("", now)
	require.NoError(t, AuthorizeS3Plan(policy, plan))
}

func TestAuthorizeS3PlanRejectsUnsealedPlan(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	plan, err := planS3Operation(req, "bucket", "key")
	require.NoError(t, err)
	require.ErrorIs(t, AuthorizeS3Plan(testAllowAllPolicy, plan), ErrMalformedS3Request)
}

func TestS3OperationPlanDefensivelyCapturesHeadersAndIAMContext(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	req := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("body"))
	req.Header.Set("x-amz-acl", "private")
	req.Header.Set("x-amz-meta-tenant", "original")
	req.Header.Set("X-Amz-Date", now.Add(-time.Second).Format("20060102T150405Z"))
	plan, err := planS3Operation(req, "bucket", "key")
	require.NoError(t, err)

	req.Method = http.MethodDelete
	req.Header.Set("x-amz-acl", "public-read")
	req.Header.Set("x-amz-meta-tenant", "mutated")
	plan = plan.withAuthorizationContext("", now)

	assert.Equal(t, http.MethodPut, plan.method)
	assert.Equal(t, "private", plan.forwardHeaders.Get("x-amz-acl"))
	assert.Equal(t, "original", plan.forwardHeaders.Get("x-amz-meta-tenant"))
	checks := buildS3IAMRequestsFromPlan(plan)
	require.Len(t, checks, 2)
	for _, check := range checks {
		assert.Equal(t, []string{"private"}, check.Context["s3:x-amz-acl"])
	}
	checks[0].Context["s3:x-amz-acl"][0] = "corrupted"
	checks[0].Context["new:key"] = []string{"new"}
	again := buildS3IAMRequestsFromPlan(plan)
	assert.Equal(t, []string{"private"}, again[0].Context["s3:x-amz-acl"])
	assert.NotContains(t, again[0].Context, "new:key")
}

func TestPlanS3OperationPreservesStreamingBodyRows(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		target    string
		objectKey string
	}{
		{name: "put object", method: http.MethodPut, target: "/bucket/key", objectKey: "key"},
		{name: "put ACL", method: http.MethodPut, target: "/bucket/key?acl", objectKey: "key"},
		{name: "put tagging", method: http.MethodPut, target: "/bucket/key?tagging", objectKey: "key"},
		{name: "upload part", method: http.MethodPut, target: "/bucket/key?partNumber=1&uploadId=u1", objectKey: "key"},
	}
	for _, tt := range tests {
		for _, unknown := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/unknown=%t", tt.name, unknown), func(t *testing.T) {
				req := httptest.NewRequest(tt.method, tt.target, strings.NewReader("streaming body"))
				if unknown {
					req.ContentLength = -1
					req.TransferEncoding = []string{"chunked"}
				}
				plan, err := planS3Operation(req, "bucket", tt.objectKey)
				require.NoError(t, err)
				assert.Equal(t, bodyStreaming, plan.bodyKind)
			})
		}
	}
}

func TestPlanS3OperationAcceptsOwnedHeaderCombinations(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		target  string
		headers http.Header
	}{
		{name: "SSE-C tuple", method: http.MethodPut, target: "/bucket/key", headers: http.Header{"X-Amz-Server-Side-Encryption-Customer-Algorithm": {"AES256"}, "X-Amz-Server-Side-Encryption-Customer-Key": {"key"}, "X-Amz-Server-Side-Encryption-Customer-Key-Md5": {"md5"}}},
		{name: "put checksum", method: http.MethodPut, target: "/bucket/key", headers: http.Header{"X-Amz-Sdk-Checksum-Algorithm": {"CRC32"}, "X-Amz-Checksum-Crc32": {"sum"}}},
		{name: "copy directives", method: http.MethodPut, target: "/bucket/key", headers: http.Header{"X-Amz-Copy-Source": {"/bucket/source"}, "X-Amz-Metadata-Directive": {"REPLACE"}, "X-Amz-Tagging-Directive": {"COPY"}}},
		{name: "create multipart checksum", method: http.MethodPost, target: "/bucket/key?uploads", headers: http.Header{"X-Amz-Checksum-Algorithm": {"SHA256"}, "X-Amz-Checksum-Type": {"COMPOSITE"}}},
		{name: "complete multipart checksum", method: http.MethodPost, target: "/bucket/key?uploadId=u1", headers: http.Header{"X-Amz-Checksum-Sha256": {"sum"}, "X-Amz-Checksum-Type": {"FULL_OBJECT"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, nil)
			req.Header = tt.headers.Clone()
			_, err := planS3Operation(req, "bucket", "key")
			require.NoError(t, err)
		})
	}
}

func FuzzPlanS3Operation(f *testing.F) {
	f.Add(http.MethodGet, "list-type=2&prefix=a", testBucket, "", "")
	f.Add(http.MethodPut, "retention", testBucket, "a.txt", "")
	f.Add(http.MethodPut, "", testBucket, "copy.txt", "/test-bucket/source.txt")
	f.Fuzz(func(t *testing.T, method, rawQuery, bucket, objectKey, copySource string) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Method = method
		req.URL.RawQuery = rawQuery
		if copySource != "" {
			req.Header.Set(copySourceHeader, copySource)
		}
		_, _ = planS3Operation(req, bucket, objectKey)
	})
}

func FuzzParseCopySource(f *testing.F) {
	f.Add("/bucket/key", "bucket")
	f.Add("bucket/key?versionId=v1", "bucket")
	f.Add("arn:aws:s3:::bucket/key", "bucket")
	f.Fuzz(func(t *testing.T, raw, bucket string) {
		_, _ = parseCopySource(raw, bucket)
	})
}

func TestBuildS3IAMRequests_Context(t *testing.T) {
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	req := httptest.NewRequest(http.MethodGet, "/test-bucket?list-type=2&delimiter=/&max-keys=25", nil)
	req.Header.Set("X-Amz-Date", now.Add(-2*time.Second).Format("20060102T150405Z"))

	checks, err := buildS3IAMRequests(req, testBucket, "", "", now)
	require.NoError(t, err)
	require.Len(t, checks, 1)

	ctx := checks[0].Context
	assert.Equal(t, []string{""}, ctx["s3:prefix"])
	assert.Equal(t, []string{"/"}, ctx["s3:delimiter"])
	assert.Equal(t, []string{"25"}, ctx["s3:max-keys"])
	assert.NotContains(t, ctx, "s3:x-amz-acl")
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

	checks, err := buildS3IAMRequests(req, "", "", "", now)
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

	checks, err := buildS3IAMRequests(req, testBucket, "", "us-west-2", now)
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

func TestParseS3IAMPolicyRejectsConditionOperatorKeyTypeMismatch(t *testing.T) {
	tests := []struct {
		operator string
		key      string
		value    string
	}{
		{operator: "StringEquals", key: "aws:SecureTransport", value: `"true"`},
		{operator: "Bool", key: "s3:max-keys", value: `true`},
		{operator: "NumericEquals", key: "aws:CurrentTime", value: `1`},
		{operator: "DateEquals", key: "s3:prefix", value: `"2026-08-06T00:00:00Z"`},
	}

	for _, tt := range tests {
		t.Run(tt.operator+"/"+tt.key, func(t *testing.T) {
			policy, err := ParseS3IAMPolicyJSON(fmt.Sprintf(`{
				"Statement": {
					"Effect": "Deny",
					"Action": "s3:*",
					"Resource": "*",
					"Condition": {%q: {%q: %s}}
				}
			}`, tt.operator, tt.key, tt.value))
			require.Nil(t, policy)
			require.ErrorIs(t, err, iam.ErrInvalidPolicy)
		})
	}
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
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Contains(t, string(body), "<Code>InvalidRequest</Code>")
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

func TestS3Auth_InvalidCredentialPolicyReturnsBadGateway(t *testing.T) {
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
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.Contains(t, string(body), "<Code>InternalError</Code>")
	assert.NotContains(t, string(body), "InvalidAccessKeyId")
}

func TestS3Auth_UnknownAccessKeyStillReturnsInvalidAccessKey(t *testing.T) {
	resolver := newTestResolver()
	resolver.credentials = func(_ context.Context, accessKeyID string) (*VirtualCredentials, error) {
		return nil, ErrResolverNotFound
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

func TestS3Auth_ListBucketsRejectsInvalidControlPlaneNamesBeforeCommit(t *testing.T) {
	for name, buckets := range map[string][]ListedVBucket{
		"invalid name":          {{Name: "bad\nbucket", CreationDate: time.Now()}},
		"duplicate":             {{Name: "alpha", CreationDate: time.Now()}, {Name: "alpha", CreationDate: time.Now()}},
		"missing creation date": {{Name: "alpha"}},
	} {
		t.Run(name, func(t *testing.T) {
			resolver := newTestResolver()
			resolver.list = func(_ context.Context, _ string) ([]ListedVBucket, error) {
				return buckets, nil
			}
			handler := S3Auth(resolver)(handleS3Request(resolver))
			server := httptest.NewServer(handler)
			t.Cleanup(server.Close)

			req := signedRequest(t, http.MethodGet, server.URL+"/", nil, unsignedPayload, validCreds)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
			assert.Contains(t, string(body), "<Code>InternalError</Code>")
			assert.NotContains(t, string(body), "<ListAllMyBucketsResult")
			assert.NotContains(t, string(body), "bad")
		})
	}
}

func TestS3AuthRejectsInvalidVirtualBucketBeforeLookup(t *testing.T) {
	for _, test := range []struct {
		name, target string
		baseHost     string
	}{
		{name: "path style", target: "http://s3.example.test/Bad_Bucket/key"},
		{name: "vhost style", target: "http://Bad_Bucket.s3.example.test/key", baseHost: "s3.example.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := newTestResolver()
			lookupCalled := false
			resolver.baseHost = func(_ context.Context, _ string) (string, bool, error) {
				return test.baseHost, test.baseHost != "", nil
			}
			resolver.vbucket = func(_ context.Context, _, _ string) (*VBucketConfig, error) {
				lookupCalled = true
				return nil, errors.New("must not be reached")
			}
			handler := S3Auth(resolver)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("downstream handler must not be reached")
			}))
			req := signedRequest(t, http.MethodGet, test.target, nil, unsignedPayload, validCreds)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			assert.Equal(t, http.StatusBadRequest, recorder.Code)
			assert.Contains(t, recorder.Body.String(), "<Code>InvalidBucketName</Code>")
			assert.False(t, lookupCalled)
		})
	}
}

func TestS3Auth_CreateBucketInterceptsWithoutVBucketLookup(t *testing.T) {
	resolver := newTestResolver()
	var vbucketLookupCalled bool
	var gotBucket, gotLocation string
	resolver.vbucket = func(_ context.Context, accessKeyID, bucketName string) (*VBucketConfig, error) {
		vbucketLookupCalled = true
		return nil, errors.New("should not lookup vbucket")
	}
	resolver.create = func(_ context.Context, accessKeyID, bucketName, locationConstraint string) error {
		require.Equal(t, testAccessKey, accessKeyID)
		gotBucket = bucketName
		gotLocation = locationConstraint
		return nil
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
	resolver.create = func(_ context.Context, accessKeyID, bucketName, locationConstraint string) error {
		createCalled = true
		return nil
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
	resolver.create = func(_ context.Context, accessKeyID, bucketName, locationConstraint string) error {
		buckets = append(buckets, ListedVBucket{Name: bucketName, CreationDate: created})
		return nil
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
