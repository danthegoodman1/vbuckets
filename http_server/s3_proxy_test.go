package http_server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleS3Request_ListRewriteStreaming_RemovesStaleContentLength(t *testing.T) {
	upstreamXML := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Name>really-long-real-bucket-name-for-testing</Name>
  <Contents><Key>tenant-abc/a/very/long/object/name/that-will-shrink.txt</Key></Contents>
</ListBucketResult>`
	upstreamContentLength := strconv.Itoa(len(upstreamXML))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Content-Length", upstreamContentLength)
		_, _ = w.Write([]byte(upstreamXML))
	}))
	t.Cleanup(upstream.Close)

	resolver := &testResolver{
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
			return &VBucketConfig{
				RealEndpoint:     upstream.URL,
				RealBucket:       "real-bucket",
				RealAccessKey:    "real-access",
				RealSecretKey:    "real-secret",
				RealRegion:       "us-east-1",
				PathPrefix:       "tenant-abc",
				RealUsePathStyle: true,
			}, nil
		},
	}

	router := chi.NewRouter()
	RegisterS3Routes(resolver)(router)
	proxy := httptest.NewServer(router)
	t.Cleanup(proxy.Close)

	req := signedRequest(t, http.MethodGet, proxy.URL+"/"+testBucket+"?list-type=2", nil, unsignedPayload, validCreds)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	gotContentLength := resp.Header.Get("Content-Length")
	if gotContentLength != "" {
		assert.NotEqual(t, upstreamContentLength, gotContentLength, "proxy should not forward stale upstream Content-Length after rewriting")
		assert.Equal(t, strconv.Itoa(len(body)), gotContentLength, "if Content-Length is present, it should match rewritten body size")
	}
	assert.Contains(t, string(body), "<Name>"+testBucket+"</Name>")
	assert.Contains(t, string(body), "<Key>a/very/long/object/name/that-will-shrink.txt</Key>")
	assert.NotContains(t, string(body), "tenant-abc/")
}

func TestHandleS3Request_CopyObjectRewritesSourceAndDestination(t *testing.T) {
	var upstreamCalled bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/real-bucket/tenant-abc/dest.txt", r.URL.Path)
		assert.Equal(t, "real-bucket/tenant-abc/source%20one.txt?versionId=v%2F1", r.Header.Get(copySourceHeader))
		assert.NotEmpty(t, r.Header.Get("Authorization"))
		assert.Equal(t, unsignedPayload, r.Header.Get("x-amz-content-sha256"))

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<CopyObjectResult><ETag>"abc123"</ETag></CopyObjectResult>`))
	}))
	t.Cleanup(upstream.Close)

	resolver := &testResolver{
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
			return &VBucketConfig{
				RealEndpoint:     upstream.URL,
				RealBucket:       "real-bucket",
				RealAccessKey:    "real-access",
				RealSecretKey:    "real-secret",
				RealRegion:       "us-east-1",
				PathPrefix:       "tenant-abc",
				RealUsePathStyle: true,
			}, nil
		},
	}

	router := chi.NewRouter()
	RegisterS3Routes(resolver)(router)
	proxy := httptest.NewServer(router)
	t.Cleanup(proxy.Close)

	req := signedRequestWithHeaders(t, http.MethodPut, proxy.URL+"/"+testBucket+"/dest.txt", nil, unsignedPayload, validCreds, map[string]string{
		copySourceHeader: "/" + testBucket + "/source%20one.txt?versionId=v/1",
	})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.True(t, upstreamCalled)
}
