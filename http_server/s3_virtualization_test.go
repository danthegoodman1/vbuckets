package http_server

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	phase2RealBucket = "real-bucket-sentinel"
	phase2RealPrefix = "tenant-prefix-sentinel"
)

func newPhase2Proxy(t *testing.T, upstream http.Handler, mutateConfig func(*VBucketConfig)) *httptest.Server {
	proxy, _ := newPhase2ProxyWithConfig(t, upstream, mutateConfig)
	return proxy
}

func newPhase2ProxyWithConfig(t *testing.T, upstream http.Handler, mutateConfig func(*VBucketConfig)) (*httptest.Server, *VBucketConfig) {
	t.Helper()
	real := httptest.NewServer(upstream)
	t.Cleanup(real.Close)

	cfg := &VBucketConfig{
		RealEndpoint:     real.URL,
		RealBucket:       phase2RealBucket,
		RealAccessKey:    "real-access-sentinel",
		RealSecretKey:    "real-secret-sentinel",
		RealRegion:       "us-east-1-sentinel",
		PathPrefix:       phase2RealPrefix,
		RealUsePathStyle: true,
		RoutingTokenKey:  testRoutingTokenKey,
	}
	if mutateConfig != nil {
		mutateConfig(cfg)
	}
	resolver := &testResolver{
		credentials: func(_ context.Context, _ string) (*VirtualCredentials, error) {
			return &VirtualCredentials{SecretKey: testSecretKey, IAMPolicy: testAllowAllPolicy}, nil
		},
		baseHost: func(_ context.Context, _ string) (string, bool, error) { return "", false, nil },
		vbucket:  func(_ context.Context, _, _ string) (*VBucketConfig, error) { return cfg, nil },
	}

	router := chi.NewRouter()
	RegisterS3Routes(resolver)(router)
	proxy := httptest.NewServer(router)
	t.Cleanup(proxy.Close)
	return proxy, cfg
}

func doPhase2Request(t *testing.T, proxy *httptest.Server, method, target string, body []byte) (*http.Response, string) {
	t.Helper()
	req := signedRequest(t, method, proxy.URL+target, body, unsignedPayload, validCreds)
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, string(data)
}

func TestVirtualNamespaceBucketAndMultipartRequestTransforms(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		target    string
		wantPath  string
		wantQuery url.Values
	}{
		{
			name:     "HeadBucket stays at bucket root",
			method:   http.MethodHead,
			target:   "/" + testBucket,
			wantPath: "/" + phase2RealBucket,
		},
		{
			name:     "ListMultipartUploads prefixes only key fields",
			method:   http.MethodGet,
			target:   "/" + testBucket + "?uploads&prefix=videos%2F&key-marker=first&upload-id-marker=TOKEN",
			wantPath: "/" + phase2RealBucket,
			wantQuery: url.Values{
				"uploads":          {""},
				"prefix":           {phase2RealPrefix + "/videos/"},
				"key-marker":       {phase2RealPrefix + "/first"},
				"upload-id-marker": {"opaque"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tt.wantPath, r.URL.EscapedPath())
				if tt.wantQuery != nil {
					assert.Equal(t, tt.wantQuery, r.URL.Query())
				}
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `<ListMultipartUploadsResult><Bucket>`+phase2RealBucket+`</Bucket></ListMultipartUploadsResult>`)
			})
			proxy, cfg := newPhase2ProxyWithConfig(t, upstream, nil)
			target := tt.target
			if strings.Contains(target, "TOKEN") {
				virtualMarker, err := encodeOpaqueToken(cfg, "upload", "opaque")
				require.NoError(t, err)
				target = strings.ReplaceAll(target, "TOKEN", url.QueryEscape(virtualMarker))
			}
			resp, _ := doPhase2Request(t, proxy, tt.method, target, nil)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

func TestVirtualNamespaceMultipartSuccessProfiles(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		target     string
		upstream   string
		wantFields []string
	}{
		{
			name:   "ListMultipartUploads",
			method: http.MethodGet,
			target: "/" + testBucket + "?uploads&prefix=videos%2F&key-marker=before",
			upstream: `<ListMultipartUploadsResult><Bucket>` + phase2RealBucket + `</Bucket><Prefix>` + phase2RealPrefix + `/videos/</Prefix>` +
				`<KeyMarker>` + phase2RealPrefix + `/before</KeyMarker><NextKeyMarker>` + phase2RealPrefix + `/after</NextKeyMarker>` +
				`<Upload><Key>` + phase2RealPrefix + `/videos/a.mp4</Key><UploadId>u1</UploadId></Upload>` +
				`<CommonPrefixes><Prefix>` + phase2RealPrefix + `/videos/sub/</Prefix></CommonPrefixes></ListMultipartUploadsResult>`,
			wantFields: []string{"<Bucket>" + testBucket + "</Bucket>", "<Prefix>videos/</Prefix>", "<KeyMarker>before</KeyMarker>", "<NextKeyMarker>after</NextKeyMarker>", "<Key>videos/a.mp4</Key>", "<Prefix>videos/sub/</Prefix>"},
		},
		{
			name:       "CreateMultipartUpload",
			method:     http.MethodPost,
			target:     "/" + testBucket + "/video.mp4?uploads",
			upstream:   `<InitiateMultipartUploadResult><Bucket>` + phase2RealBucket + `</Bucket><Key>` + phase2RealPrefix + `/video.mp4</Key><UploadId>u1</UploadId></InitiateMultipartUploadResult>`,
			wantFields: []string{"<Bucket>" + testBucket + "</Bucket>", "<Key>video.mp4</Key>", "<UploadId>vb1.upload."},
		},
		{
			name:       "ListParts",
			method:     http.MethodGet,
			target:     "/" + testBucket + "/video.mp4?uploadId=TOKEN",
			upstream:   `<ListPartsResult><Bucket>` + phase2RealBucket + `</Bucket><Key>` + phase2RealPrefix + `/video.mp4</Key><UploadId>u1</UploadId><PartNumberMarker>0</PartNumberMarker><NextPartNumberMarker>2</NextPartNumberMarker><MaxParts>1000</MaxParts><IsTruncated>false</IsTruncated></ListPartsResult>`,
			wantFields: []string{"<Bucket>" + testBucket + "</Bucket>", "<Key>video.mp4</Key>", "<UploadId>TOKEN</UploadId>", "<PartNumberMarker>0</PartNumberMarker>"},
		},
		{
			name:   "CompleteMultipartUpload",
			method: http.MethodPost,
			target: "/" + testBucket + "/video.mp4?uploadId=TOKEN",
			upstream: `<CompleteMultipartUploadResult><Location>http://real-endpoint-sentinel/` + phase2RealBucket + `/` + phase2RealPrefix + `/video.mp4</Location>` +
				`<Bucket>` + phase2RealBucket + `</Bucket><Key>` + phase2RealPrefix + `/video.mp4</Key><ETag>etag</ETag></CompleteMultipartUploadResult>`,
			wantFields: []string{"<Bucket>" + testBucket + "</Bucket>", "<Key>video.mp4</Key>", "<ETag>etag</ETag>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, tt.upstream)
			})
			proxy, cfg := newPhase2ProxyWithConfig(t, upstream, nil)
			virtualUploadID, err := encodeOpaqueToken(cfg, "upload", "u1")
			require.NoError(t, err)
			target := strings.ReplaceAll(tt.target, "TOKEN", url.QueryEscape(virtualUploadID))
			body := []byte(nil)
			if strings.Contains(target, "uploadId=") && tt.method == http.MethodPost {
				body = []byte(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag</ETag></Part></CompleteMultipartUpload>`)
			}
			resp, got := doPhase2Request(t, proxy, tt.method, target, body)
			require.Equal(t, http.StatusOK, resp.StatusCode, got)
			for _, want := range tt.wantFields {
				want = strings.ReplaceAll(want, "TOKEN", virtualUploadID)
				assert.Contains(t, got, want)
			}
			assert.NotContains(t, got, phase2RealBucket)
			assert.NotContains(t, got, phase2RealPrefix)
			assert.NotContains(t, got, "real-endpoint-sentinel")
		})
	}
}

func TestVirtualNamespaceSanitizesErrorsRedirectsAndConnectionHeaders(t *testing.T) {
	statuses := []int{http.StatusTemporaryRedirect, http.StatusBadRequest, http.StatusInternalServerError}
	for _, status := range statuses {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Connection", "X-Backend-Endpoint, X-Real-Bucket")
				w.Header().Set("X-Backend-Endpoint", "real-endpoint-sentinel")
				w.Header().Set("X-Real-Bucket", phase2RealBucket)
				w.Header().Set("Location", "http://real-endpoint-sentinel/"+phase2RealBucket+"/"+phase2RealPrefix+"/secret")
				w.Header().Set("Server", "real-endpoint-sentinel")
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `<Error><Code>TemporaryRedirect</Code><Message>go to real-endpoint-sentinel</Message><BucketName>`+phase2RealBucket+`</BucketName><Key>`+phase2RealPrefix+`/secret</Key><Endpoint>real-endpoint-sentinel</Endpoint><Region>us-east-1-sentinel</Region></Error>`)
			})
			proxy := newPhase2Proxy(t, upstream, nil)
			resp, body := doPhase2Request(t, proxy, http.MethodGet, "/"+testBucket+"/secret", nil)
			wantStatus := status
			if status >= 300 && status < 400 {
				wantStatus = http.StatusBadGateway
			}
			assert.Equal(t, wantStatus, resp.StatusCode)
			if status >= 300 && status < 400 {
				assert.Empty(t, resp.Header.Get("Location"))
			}
			for _, sentinel := range []string{"real-endpoint-sentinel", phase2RealBucket, phase2RealPrefix, "us-east-1-sentinel"} {
				assert.NotContains(t, body, sentinel)
				for name, values := range resp.Header {
					assert.NotContains(t, strings.Join(values, ","), sentinel, name)
				}
			}
			assert.Empty(t, resp.Header.Get("X-Backend-Endpoint"))
			assert.Empty(t, resp.Header.Get("X-Real-Bucket"))
			assert.Empty(t, resp.Header.Get("Server"))
		})
	}
}

func TestVirtualNamespaceHEADRedirectIsControlledAndBodylessOverHTTP(t *testing.T) {
	proxy := newPhase2Proxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://real-endpoint-sentinel/"+phase2RealBucket+"/"+phase2RealPrefix)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}), nil)
	resp, body := doPhase2Request(t, proxy, http.MethodHead, "/"+testBucket+"/key", nil)
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
	assert.Empty(t, body)
}

func TestVirtualNamespaceRejectsMalformedBackendMappingBeforeUpstream(t *testing.T) {
	called := false
	proxy := newPhase2Proxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}), func(cfg *VBucketConfig) {
		cfg.RealEndpoint = "http://user:password@real-endpoint-sentinel/path?query=bad"
	})

	resp, body := doPhase2Request(t, proxy, http.MethodGet, "/"+testBucket+"/key", nil)
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode, body)
	assert.False(t, called)
	assert.NotContains(t, body, "real-endpoint-sentinel")
}

func TestVirtualNamespaceOpaqueUploadIDRoundTripsWithoutDisclosure(t *testing.T) {
	realUploadID := "opaque/" + phase2RealBucket + "/" + phase2RealPrefix + "/u+1"
	var listPartsUploadID string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		switch {
		case r.Method == http.MethodPost && r.URL.Query().Has("uploads"):
			_, _ = io.WriteString(w, `<InitiateMultipartUploadResult><Bucket>`+phase2RealBucket+`</Bucket><Key>`+phase2RealPrefix+`/video.mp4</Key><UploadId>`+realUploadID+`</UploadId></InitiateMultipartUploadResult>`)
		case r.Method == http.MethodGet && r.URL.Query().Has("uploadId"):
			listPartsUploadID = r.URL.Query().Get("uploadId")
			_, _ = io.WriteString(w, `<ListPartsResult><Bucket>`+phase2RealBucket+`</Bucket><Key>`+phase2RealPrefix+`/video.mp4</Key><UploadId>`+realUploadID+`</UploadId><PartNumberMarker>0</PartNumberMarker><NextPartNumberMarker>0</NextPartNumberMarker><MaxParts>1000</MaxParts><IsTruncated>false</IsTruncated></ListPartsResult>`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	proxy := newPhase2Proxy(t, upstream, nil)

	resp, createBody := doPhase2Request(t, proxy, http.MethodPost, "/"+testBucket+"/video.mp4?uploads", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, createBody)
	assert.NotContains(t, createBody, phase2RealBucket)
	assert.NotContains(t, createBody, phase2RealPrefix)
	match := regexp.MustCompile(`<UploadId>([^<]+)</UploadId>`).FindStringSubmatch(createBody)
	require.Len(t, match, 2, createBody)
	virtualUploadID := match[1]
	assert.NotEqual(t, realUploadID, virtualUploadID)

	resp, listBody := doPhase2Request(t, proxy, http.MethodGet, "/"+testBucket+"/video.mp4?uploadId="+url.QueryEscape(virtualUploadID), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, listBody)
	assert.Equal(t, realUploadID, listPartsUploadID)
	assert.NotContains(t, listBody, phase2RealBucket)
	assert.NotContains(t, listBody, phase2RealPrefix)
}

func TestVirtualNamespaceVersionIDRoundTripsAndRawIDsFailClosed(t *testing.T) {
	const originVersion = "origin/version::real-bucket-sentinel"
	var seenVersion string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if version := r.URL.Query().Get("versionId"); version != "" {
			seenVersion = version
		}
		w.Header().Set("X-Amz-Version-Id", originVersion)
		_, _ = io.WriteString(w, "object")
	})
	proxy := newPhase2Proxy(t, upstream, nil)

	resp, body := doPhase2Request(t, proxy, http.MethodGet, "/"+testBucket+"/key", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	virtualVersion := resp.Header.Get("X-Amz-Version-Id")
	require.NotEmpty(t, virtualVersion)
	assert.NotContains(t, virtualVersion, originVersion)

	resp, body = doPhase2Request(t, proxy, http.MethodGet, "/"+testBucket+"/key?versionId="+url.QueryEscape(virtualVersion), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	assert.Equal(t, originVersion, seenVersion)

	seenVersion = ""
	resp, body = doPhase2Request(t, proxy, http.MethodGet, "/"+testBucket+"/key?versionId=raw-origin-id", nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, body)
	assert.Empty(t, seenVersion)
}

func TestVirtualNamespacePreservesDecodedKeyIdentityAcrossEscapes(t *testing.T) {
	tests := []struct {
		rawKey  string
		wantKey string
	}{
		{rawKey: "space%20name", wantKey: "space name"},
		{rawKey: "plus+name", wantKey: "plus+name"},
		{rawKey: "percent%2525", wantKey: "percent%25"},
		{rawKey: "encoded%2Fslash", wantKey: "encoded/slash"},
		{rawKey: "%E2%98%83-unicode", wantKey: "☃-unicode"},
		{rawKey: "repeat//slash", wantKey: "repeat//slash"},
	}
	for _, tt := range tests {
		t.Run(tt.rawKey, func(t *testing.T) {
			upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/"+phase2RealBucket+"/"+phase2RealPrefix+"/"+tt.wantKey, r.URL.Path)
				_, _ = io.WriteString(w, "object")
			})
			proxy := newPhase2Proxy(t, upstream, nil)
			resp, body := doPhase2Request(t, proxy, http.MethodGet, "/"+testBucket+"/"+tt.rawKey, nil)
			require.Equal(t, http.StatusOK, resp.StatusCode, body)
			assert.Equal(t, "object", body)
		})
	}
}

func TestVirtualNamespaceStreamsStoredGzipObjectBytesWithoutTransportDecompression(t *testing.T) {
	var compressed bytes.Buffer
	zipper := gzip.NewWriter(&compressed)
	_, err := zipper.Write([]byte("stored object bytes"))
	require.NoError(t, err)
	require.NoError(t, zipper.Close())
	want := append([]byte(nil), compressed.Bytes()...)

	proxy := newPhase2Proxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Accept-Encoding"), "proxy transport must not negotiate transparent decompression")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("ETag", `"stored-gzip"`)
		w.Header().Set("Content-Length", fmt.Sprint(len(want)))
		_, _ = w.Write(want)
	}), nil)
	req := signedRequest(t, http.MethodGet, proxy.URL+"/"+testBucket+"/gzip.bin", nil, unsignedPayload, validCreds)
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
	assert.Equal(t, `"stored-gzip"`, resp.Header.Get("ETag"))
}

func TestResolveBucketPreservesPathAndVHostKeyIdentity(t *testing.T) {
	resolver := &testResolver{baseHost: func(_ context.Context, hostname string) (string, bool, error) {
		return "s3.example.test", true, nil
	}}
	for _, test := range []struct {
		name, host, target, bucket, key string
		vhost                           bool
	}{
		{name: "path style", host: "s3.example.test", target: "/bucket/a%20b//c", bucket: "bucket", key: "a b//c"},
		{name: "vhost style", host: "bucket.s3.example.test", target: "/a%20b//c", bucket: "bucket", key: "a b//c", vhost: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+test.host+test.target, nil)
			bucket, key, isVHost, err := resolveBucket(resolver, req)
			require.NoError(t, err)
			assert.Equal(t, test.bucket, bucket)
			assert.Equal(t, test.key, key)
			assert.Equal(t, test.vhost, isVHost)
		})
	}
}

func TestVirtualNamespaceSharedBackendMultipartLifecycleAndPagination(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	originRequests := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realKey := strings.TrimPrefix(r.URL.Path, "/"+phase2RealBucket+"/")
		prefix, _, _ := strings.Cut(realKey, "/")
		if r.Method == http.MethodGet && r.URL.Query().Has("uploads") {
			prefix = strings.TrimSuffix(r.URL.Query().Get("prefix"), "/")
			realKey = prefix + "/video +%.mp4"
		}
		originUploadID := "origin-upload::" + realKey
		mu.Lock()
		originRequests++
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		switch {
		case r.Method == http.MethodPost && r.URL.Query().Has("uploads"):
			_, _ = io.WriteString(w, `<InitiateMultipartUploadResult><Bucket>`+phase2RealBucket+`</Bucket><Key>`+realKey+`</Key><UploadId>`+originUploadID+`</UploadId></InitiateMultipartUploadResult>`)
		case r.Method == http.MethodPut && r.URL.Query().Has("partNumber"):
			assert.Equal(t, originUploadID, r.URL.Query().Get("uploadId"))
			w.Header().Set("ETag", `"part-etag"`)
		case r.Method == http.MethodGet && r.URL.Query().Has("uploadId"):
			assert.Equal(t, originUploadID, r.URL.Query().Get("uploadId"))
			_, _ = io.WriteString(w, `<ListPartsResult><Bucket>`+phase2RealBucket+`</Bucket><Key>`+realKey+`</Key><UploadId>`+originUploadID+`</UploadId><PartNumberMarker>0</PartNumberMarker><NextPartNumberMarker>1</NextPartNumberMarker><MaxParts>1000</MaxParts><IsTruncated>false</IsTruncated><Part><PartNumber>1</PartNumber><ETag>"part-etag"</ETag></Part></ListPartsResult>`)
		case r.Method == http.MethodPost && r.URL.Query().Has("uploadId"):
			assert.Equal(t, originUploadID, r.URL.Query().Get("uploadId"))
			_, _ = io.WriteString(w, `<CompleteMultipartUploadResult><Location>origin</Location><Bucket>`+phase2RealBucket+`</Bucket><Key>`+realKey+`</Key><ETag>"complete"</ETag></CompleteMultipartUploadResult>`)
		case r.Method == http.MethodDelete && r.URL.Query().Has("uploadId"):
			assert.Equal(t, originUploadID, r.URL.Query().Get("uploadId"))
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Query().Has("uploads"):
			assert.Equal(t, prefix+"/", r.URL.Query().Get("prefix"))
			if marker := r.URL.Query().Get("upload-id-marker"); marker != "" {
				assert.Equal(t, originUploadID, marker)
				_, _ = io.WriteString(w, `<ListMultipartUploadsResult><Bucket>`+phase2RealBucket+`</Bucket><Prefix>`+prefix+`/</Prefix><UploadIdMarker>`+originUploadID+`</UploadIdMarker><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>`)
				return
			}
			_, _ = io.WriteString(w, `<ListMultipartUploadsResult><Bucket>`+phase2RealBucket+`</Bucket><Prefix>`+prefix+`/</Prefix><NextUploadIdMarker>`+originUploadID+`</NextUploadIdMarker><Upload><Key>`+realKey+`</Key><UploadId>`+originUploadID+`</UploadId></Upload><IsTruncated>true</IsTruncated></ListMultipartUploadsResult>`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(upstream.Close)

	resolver := &testResolver{
		credentials: func(_ context.Context, _ string) (*VirtualCredentials, error) {
			return &VirtualCredentials{SecretKey: testSecretKey, IAMPolicy: testAllowAllPolicy}, nil
		},
		baseHost: func(_ context.Context, _ string) (string, bool, error) { return "", false, nil },
		vbucket: func(_ context.Context, _, bucket string) (*VBucketConfig, error) {
			prefixes := map[string]string{"tenant-a-bucket": "tenant-a", "tenant-b-bucket": "tenant-b"}
			prefix, ok := prefixes[bucket]
			if !ok {
				return nil, fmt.Errorf("unknown bucket")
			}
			return &VBucketConfig{
				RealEndpoint: upstream.URL, RealBucket: phase2RealBucket,
				RealAccessKey: "real-access", RealSecretKey: "real-secret", RealRegion: "us-east-1",
				PathPrefix: prefix, RealUsePathStyle: true, RoutingTokenKey: testRoutingTokenKey,
			}, nil
		},
	}
	router := chi.NewRouter()
	RegisterS3Routes(resolver)(router)
	proxy := httptest.NewServer(router)
	t.Cleanup(proxy.Close)

	virtualUploadIDs := make(map[string]string)
	t.Run("concurrent tenants", func(t *testing.T) {
		for _, bucket := range []string{"tenant-a-bucket", "tenant-b-bucket"} {
			bucket := bucket
			t.Run(bucket, func(t *testing.T) {
				t.Parallel()
				key := "video +%.mp4"
				baseTarget := "/" + bucket + "/" + url.PathEscape(key)
				resp, createBody := doPhase2Request(t, proxy, http.MethodPost, baseTarget+"?uploads", nil)
				require.Equal(t, http.StatusOK, resp.StatusCode, createBody)
				virtualUploadID := between(createBody, "<UploadId>", "</UploadId>")
				require.NotEmpty(t, virtualUploadID)
				assert.NotContains(t, createBody, phase2RealBucket)
				mu.Lock()
				virtualUploadIDs[bucket] = virtualUploadID
				mu.Unlock()

				resp, partBody := doPhase2Request(t, proxy, http.MethodPut, baseTarget+"?partNumber=1&uploadId="+url.QueryEscape(virtualUploadID), []byte("part"))
				require.Equal(t, http.StatusOK, resp.StatusCode, partBody)
				assert.Equal(t, `"part-etag"`, resp.Header.Get("ETag"))

				resp, partsBody := doPhase2Request(t, proxy, http.MethodGet, baseTarget+"?uploadId="+url.QueryEscape(virtualUploadID), nil)
				require.Equal(t, http.StatusOK, resp.StatusCode, partsBody)
				assert.Contains(t, partsBody, `<UploadId>`+virtualUploadID+`</UploadId>`)
				assert.NotContains(t, partsBody, "origin-upload")

				complete := []byte(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"part-etag"</ETag></Part></CompleteMultipartUpload>`)
				resp, completeBody := doPhase2Request(t, proxy, http.MethodPost, baseTarget+"?uploadId="+url.QueryEscape(virtualUploadID), complete)
				require.Equal(t, http.StatusOK, resp.StatusCode, completeBody)
				assert.Contains(t, completeBody, `<Location>/`+bucket+`/`+awsURIEncode(key)+`</Location>`)
				assert.Contains(t, completeBody, `<Bucket>`+bucket+`</Bucket>`)
				assert.Contains(t, completeBody, `<Key>`+key+`</Key>`)
				assert.NotContains(t, completeBody, phase2RealBucket)

				resp, listBody := doPhase2Request(t, proxy, http.MethodGet, "/"+bucket+"?uploads", nil)
				require.Equal(t, http.StatusOK, resp.StatusCode, listBody)
				nextMarker := between(listBody, "<NextUploadIdMarker>", "</NextUploadIdMarker>")
				require.NotEmpty(t, nextMarker)
				assert.Contains(t, listBody, `<Key>`+key+`</Key>`)
				assert.NotContains(t, listBody, "tenant-a/")
				assert.NotContains(t, listBody, "tenant-b/")

				resp, nextBody := doPhase2Request(t, proxy, http.MethodGet, "/"+bucket+"?uploads&upload-id-marker="+url.QueryEscape(nextMarker), nil)
				require.Equal(t, http.StatusOK, resp.StatusCode, nextBody)
				assert.Contains(t, nextBody, `<UploadIdMarker>`+nextMarker+`</UploadIdMarker>`)

				resp, abortBody := doPhase2Request(t, proxy, http.MethodDelete, baseTarget+"?uploadId="+url.QueryEscape(virtualUploadID), nil)
				require.Equal(t, http.StatusNoContent, resp.StatusCode, abortBody)
			})
		}
	})

	mu.Lock()
	tenantAUploadID := virtualUploadIDs["tenant-a-bucket"]
	beforeReplay := originRequests
	mu.Unlock()
	require.NotEmpty(t, tenantAUploadID)
	replayTarget := "/tenant-b-bucket/" + url.PathEscape("video +%.mp4") + "?partNumber=2&uploadId=" + url.QueryEscape(tenantAUploadID)
	resp, replayBody := doPhase2Request(t, proxy, http.MethodPut, replayTarget, []byte("cross-tenant replay"))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, replayBody)
	mu.Lock()
	assert.Equal(t, beforeReplay, originRequests, "a tenant-A routing token must fail before tenant-B origin access")
	requests := append([]string(nil), seen...)
	mu.Unlock()

	for _, request := range requests {
		assert.False(t, strings.Contains(request, "tenant-a/../") || strings.Contains(request, "tenant-b/../"))
	}
}
