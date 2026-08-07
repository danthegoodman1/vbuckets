package http_server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleS3Request_ListRewriteStreaming_RemovesStaleContentLength(t *testing.T) {
	upstreamXML := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Name>real-bucket</Name>
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
				RoutingTokenKey:  testRoutingTokenKey,
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
		_, _ = w.Write([]byte(`<CopyObjectResult><ETag>"abc123"</ETag><LastModified>2026-08-06T00:00:00Z</LastModified></CopyObjectResult>`))
	}))
	t.Cleanup(upstream.Close)
	virtualVersion, err := encodeOpaqueToken(&VBucketConfig{RealEndpoint: upstream.URL, RealBucket: "real-bucket", PathPrefix: "tenant-abc", RoutingTokenKey: testRoutingTokenKey}, "version", "v/1")
	require.NoError(t, err)

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
				RoutingTokenKey:  testRoutingTokenKey,
			}, nil
		},
	}

	router := chi.NewRouter()
	RegisterS3Routes(resolver)(router)
	proxy := httptest.NewServer(router)
	t.Cleanup(proxy.Close)

	req := signedRequestWithHeaders(t, http.MethodPut, proxy.URL+"/"+testBucket+"/dest.txt", nil, unsignedPayload, validCreds, map[string]string{
		copySourceHeader: "/" + testBucket + "/source%20one.txt?versionId=" + url.QueryEscape(virtualVersion),
	})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.True(t, upstreamCalled)
}

func TestHandleS3Request_CompleteMultipartReplaysExactValidatedBody(t *testing.T) {
	wantBody := []byte("  <CompleteMultipartUpload>\n" +
		"    <Part><PartNumber>1</PartNumber><ETag>\"etag-1\"</ETag></Part>\n" +
		"    <Part><PartNumber>2</PartNumber><ETag>\"etag-2\"</ETag></Part>\n" +
		"  </CompleteMultipartUpload>\n")
	var upstreamCalled bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/real-bucket/tenant-abc/video.mp4", r.URL.Path)
		assert.Equal(t, "upload-1", r.URL.Query().Get("uploadId"))
		assert.Equal(t, int64(len(wantBody)), r.ContentLength)
		gotBody, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(wantBody, gotBody), "validated control XML must reach upstream byte-for-byte")

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<CompleteMultipartUploadResult><Location>origin-location</Location><Bucket>real-bucket</Bucket><Key>tenant-abc/video.mp4</Key><ETag>"complete"</ETag></CompleteMultipartUploadResult>`))
	}))
	t.Cleanup(upstream.Close)
	virtualUploadID, err := encodeOpaqueToken(&VBucketConfig{RealEndpoint: upstream.URL, RealBucket: "real-bucket", PathPrefix: "tenant-abc", RoutingTokenKey: testRoutingTokenKey}, "upload", "upload-1")
	require.NoError(t, err)

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
				RoutingTokenKey:  testRoutingTokenKey,
			}, nil
		},
	}

	router := chi.NewRouter()
	RegisterS3Routes(resolver)(router)
	proxy := httptest.NewServer(router)
	t.Cleanup(proxy.Close)

	req := signedRequest(t, http.MethodPost, proxy.URL+"/"+testBucket+"/video.mp4?uploadId="+url.QueryEscape(virtualUploadID), wantBody, unsignedPayload, validCreds)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, string(responseBody))
	assert.True(t, upstreamCalled)
}

func TestCopyOutboundRequestHeadersUsesExplicitSafeContract(t *testing.T) {
	source := http.Header{
		"Connection":             {"Range, X-Amz-Meta-Nominated"},
		"Range":                  {"bytes=0-10"},
		"X-Amz-Meta-Nominated":   {"drop-me"},
		"X-Amz-Meta-Keep":        {"keep-me"},
		"Content-Type":           {"application/octet-stream"},
		"If-Match":               {`"etag"`},
		"If-Range":               {`"etag"`},
		"Accept-Encoding":        {"gzip"},
		"Cookie":                 {"session=secret"},
		"Forwarded":              {"for=internal"},
		"X-Forwarded-Host":       {"internal.example"},
		"X-Http-Method-Override": {"DELETE"},
		"Proxy-Authorization":    {"secret"},
	}
	destination := make(http.Header)
	copyOutboundRequestHeaders(source, destination, operationGetObject)

	assert.Empty(t, destination.Get("Connection"))
	assert.Empty(t, destination.Get("Range"), "Connection-nominated headers are hop-by-hop")
	assert.Empty(t, destination.Get("X-Amz-Meta-Nominated"))
	assert.Empty(t, destination.Get("Cookie"))
	assert.Empty(t, destination.Get("Forwarded"))
	assert.Empty(t, destination.Get("X-Forwarded-Host"))
	assert.Empty(t, destination.Get("X-Http-Method-Override"))
	assert.Empty(t, destination.Get("Proxy-Authorization"))
	assert.Equal(t, `"etag"`, destination.Get("If-Match"))
	assert.Equal(t, `"etag"`, destination.Get("If-Range"))
	assert.Equal(t, "gzip", destination.Get("Accept-Encoding"))
	assert.Empty(t, destination.Get("Content-Type"))

	putDestination := make(http.Header)
	copyOutboundRequestHeaders(source, putDestination, operationPutObject)
	assert.Equal(t, "keep-me", putDestination.Get("X-Amz-Meta-Keep"))
	assert.Equal(t, "application/octet-stream", putDestination.Get("Content-Type"))
	assert.Empty(t, putDestination.Get("Accept-Encoding"))
}
