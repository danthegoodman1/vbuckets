package e2e

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	apiv1 "github.com/danthegoodman1/vbuckets/api/v1"
	"github.com/danthegoodman1/vbuckets/internal/s3test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Runs in the short/race suite: only the origin's storage is a stub. HTTP,
// gRPC, watch invalidation, credential caches, IAM, and forwarding are real.
func TestPerKeyIAMConformance(t *testing.T) {
	var originCalls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originCalls.Add(1)
		assert.Contains(t, r.Header.Get("Authorization"), s3test.AccessKey)
		assert.True(t, strings.HasPrefix(r.URL.Path, "/"+s3test.Bucket))
		physicalKey := strings.TrimPrefix(r.URL.Path, "/"+s3test.Bucket+"/")
		w.Header().Set("Content-Type", "application/xml")
		switch {
		case r.Header.Get("X-Amz-Copy-Source") != "":
			assert.Equal(t, s3test.Bucket+"/shared/copy-source/item", r.Header.Get("X-Amz-Copy-Source"))
			_, _ = io.WriteString(w, `<CopyObjectResult><ETag>"copied"</ETag><LastModified>2026-09-19T00:00:00Z</LastModified></CopyObjectResult>`)
		case r.Method == http.MethodPost && r.URL.Query().Has("uploads"):
			_, _ = fmt.Fprintf(w, `<InitiateMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><UploadId>origin-upload</UploadId></InitiateMultipartUploadResult>`, s3test.Bucket, physicalKey)
		case r.Method == http.MethodPost && r.URL.Query().Has("uploadId"):
			assert.Equal(t, "origin-upload", r.URL.Query().Get("uploadId"))
			_, _ = fmt.Fprintf(w, `<CompleteMultipartUploadResult><Location>origin</Location><Bucket>%s</Bucket><Key>%s</Key><ETag>"complete"</ETag></CompleteMultipartUploadResult>`, s3test.Bucket, physicalKey)
		case r.Method == http.MethodGet && r.URL.Query().Has("list-type"):
			assert.Equal(t, "shared/public/", r.URL.Query().Get("prefix"))
			_, _ = fmt.Fprintf(w, `<ListBucketResult><Name>%s</Name><Prefix>shared/public/</Prefix><IsTruncated>false</IsTruncated></ListBucketResult>`, s3test.Bucket)
		case r.Method == http.MethodPut:
			if r.URL.Query().Has("uploadId") {
				assert.Equal(t, "origin-upload", r.URL.Query().Get("uploadId"))
			}
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("ETag", `"part"`)
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, "object:"+physicalKey)
		default:
			t.Errorf("unexpected origin operation: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(origin.Close)
	readPolicy := func(name string) string {
		t.Helper()
		data, err := os.ReadFile("../examples/iam/" + name + ".json")
		require.NoError(t, err)
		return string(data)
	}
	readerPolicy, writerPolicy := readPolicy("scoped-reader"), readPolicy("writer")
	implementation := &testControlPlane{
		originEndpoint: origin.URL, revision: 1, changes: make(chan *apiv1.WatchEvent, 16), createdBuckets: make(map[string]time.Time),
		identities: map[string]*testIdentity{
			"reader": {secret: "reader-secret", policyJSON: readerPolicy, buckets: map[string]string{"photos": "shared", "archive": "archive"}},
			"writer": {secret: "writer-secret", policyJSON: writerPolicy, buckets: map[string]string{"photos": "shared"}},
		},
	}
	cp, proxy := setupControlPlaneProxy(t, implementation)

	// Assert both the public result and the origin boundary. A denial from the
	// permissive origin would not prove that the proxy enforces the key policy.
	request := func(t *testing.T, key, method, path, body string, headers map[string]string, wantStatus int, wantOrigin bool) string {
		t.Helper()
		before := originCalls.Load()
		req, err := http.NewRequestWithContext(t.Context(), method, proxy.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
		for name, value := range headers {
			req.Header.Set(name, value)
		}
		require.NoError(t, awsv4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: key, SecretAccessKey: key + "-secret"}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now()))
		resp, err := proxy.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, wantStatus, resp.StatusCode, string(data))
		if wantStatus == http.StatusForbidden {
			require.Contains(t, string(data), "<Code>AccessDenied</Code>")
		}
		delta := int64(0)
		if wantOrigin {
			delta = 1
		}
		require.Equal(t, delta, originCalls.Load()-before, "origin calls for %s %s with key %s", method, path, key)
		return string(data)
	}
	cases := []struct {
		name, key, method, path string
		headers                 map[string]string
		allowed                 bool
	}{
		{"reader gets shared object", "reader", "GET", "/photos/public/item", nil, true},
		{"writer cannot read same object", "writer", "GET", "/photos/public/item", nil, false},
		{"writer puts shared object", "writer", "PUT", "/photos/public/item", nil, true},
		{"reader cannot write same object", "reader", "PUT", "/photos/public/item", nil, false},
		{"explicit deny overrides reader allow", "reader", "GET", "/photos/public/private/item", nil, false},
		{"reader prefix implicit deny", "reader", "GET", "/photos/elsewhere/item", nil, false},
		{"same reader key writes other bucket", "reader", "PUT", "/archive/inbox/item", nil, true},
		{"same reader key cannot read other bucket", "reader", "GET", "/archive/inbox/item", nil, false},
		{"other bucket prefix denied", "reader", "PUT", "/archive/elsewhere/item", nil, false},
		{"list allowed prefix", "reader", "GET", "/photos?list-type=2&prefix=public%2F", nil, true},
		{"unrestricted list denied", "reader", "GET", "/photos?list-type=2", nil, false},
		{"writer lacks list permission", "writer", "GET", "/photos?list-type=2&prefix=public%2F", nil, false},
		{"copy requires both actions", "writer", "PUT", "/photos/public/copy", map[string]string{"X-Amz-Copy-Source": "/photos/copy-source/item"}, true},
		{"copy missing source read", "writer", "PUT", "/photos/public/copy", map[string]string{"X-Amz-Copy-Source": "/photos/public/item"}, false},
		{"copy missing destination write", "reader", "PUT", "/photos/public/copy", map[string]string{"X-Amz-Copy-Source": "/photos/public/item"}, false},
		{"put ACL needs separate permission", "writer", "PUT", "/photos/public/item", map[string]string{"X-Amz-Acl": "private"}, false},
		{"put tagging needs separate permission", "writer", "PUT", "/photos/public/item", map[string]string{"X-Amz-Tagging": "type=public"}, false},
	}
	for _, cacheState := range []string{"initial", "warm"} {
		for _, tt := range cases {
			t.Run(cacheState+"/"+tt.name, func(t *testing.T) {
				want := http.StatusForbidden
				if tt.allowed {
					want = http.StatusOK
				}
				request(t, tt.key, tt.method, tt.path, "", tt.headers, want, tt.allowed)
			})
		}
	}
	t.Run("ListBuckets uses per-key inventory", func(t *testing.T) {
		parseNames := func(body string) []string {
			var result struct {
				Buckets []struct{ Name string } `xml:"Buckets>Bucket"`
			}
			require.NoError(t, xml.Unmarshal([]byte(body), &result))
			var names []string
			for _, bucket := range result.Buckets {
				names = append(names, bucket.Name)
			}
			return names
		}
		require.ElementsMatch(t, []string{"photos", "archive"}, parseNames(request(t, "reader", "GET", "/", "", nil, 200, false)))
		require.Equal(t, []string{"photos"}, parseNames(request(t, "writer", "GET", "/", "", nil, 200, false)))
	})
	t.Run("multipart uses key policy on every request", func(t *testing.T) {
		body := request(t, "writer", "POST", "/photos/uploads/item?uploads", "", nil, 200, true)
		var created struct {
			UploadID string `xml:"UploadId"`
		}
		require.NoError(t, xml.Unmarshal([]byte(body), &created))
		require.True(t, strings.HasPrefix(created.UploadID, "vb1.upload."))
		path := "/photos/uploads/item?uploadId=" + url.QueryEscape(created.UploadID)
		request(t, "writer", "PUT", path+"&partNumber=1", "part", nil, 200, true)
		request(t, "reader", "PUT", path+"&partNumber=1", "part", nil, 403, false)
		request(t, "reader", "POST", "/photos/uploads/item?uploads", "", nil, 403, false)
		request(t, "writer", "GET", path, "", nil, 403, false)    // ListParts is a separate action.
		request(t, "writer", "DELETE", path, "", nil, 403, false) // So is AbortMultipartUpload.
		complete := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"part"</ETag></Part></CompleteMultipartUpload>`
		request(t, "reader", "POST", path, complete, nil, 403, false)
		request(t, "writer", "POST", path, complete, nil, 200, true)
	})
	lookupCounts := func() (int, int) {
		implementation.mu.Lock()
		defer implementation.mu.Unlock()
		return implementation.credentialLookups["reader"], implementation.credentialLookups["writer"]
	}
	readers, writers := lookupCounts()
	require.Equal(t, 1, readers, "reader policy should be cached across requests")
	require.Equal(t, 1, writers, "writer policy must have its own cache entry")
	t.Run("invalid policy update leaves current policy and revision intact", func(t *testing.T) {
		_, err := implementation.setPolicy("reader", `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*","Principal":"*"}}`)
		require.Error(t, err)
		require.Equal(t, uint64(1), cp.Status().Revision)
		implementation.mu.Lock()
		revision := implementation.revision
		implementation.mu.Unlock()
		require.Equal(t, uint64(1), revision)
		request(t, "reader", "GET", "/photos/public/item", "", nil, 200, true)
	})
	t.Run("watch update replaces a warmed policy for only that key", func(t *testing.T) {
		revision, err := implementation.setPolicy("reader", `{"Statement":{"Effect":"Deny","Action":"s3:*","Resource":"*"}}`)
		require.NoError(t, err)
		require.Eventually(t, func() bool { state := cp.Status(); return state.Ready && state.Revision == revision }, time.Second, time.Millisecond)
		request(t, "reader", "GET", "/photos/public/item", "", nil, 403, false)
		request(t, "reader", "GET", "/", "", nil, 403, false)
		request(t, "writer", "PUT", "/photos/public/item", "", nil, 200, true)
		readers, writers = lookupCounts()
		require.Equal(t, 2, readers, "invalidated policy must reload before authorization")
		require.Equal(t, 1, writers, "unmodified key should retain its cached policy")
		revision, err = implementation.setPolicy("reader", readerPolicy)
		require.NoError(t, err)
		require.Eventually(t, func() bool { state := cp.Status(); return state.Ready && state.Revision == revision }, time.Second, time.Millisecond)
		request(t, "reader", "GET", "/photos/public/item", "", nil, 200, true)
	})
}
