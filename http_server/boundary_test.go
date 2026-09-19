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

	"github.com/stretchr/testify/require"
)

func boundaryResolverForOrigin(endpoint string) *testResolver {
	resolver := newTestResolver()
	resolver.vbucket = func(context.Context, string, string) (*VBucketConfig, error) {
		return &VBucketConfig{RealEndpoint: endpoint, RealBucket: "real-bucket", RealAccessKey: "real-access", RealSecretKey: "real-secret", RealRegion: "us-east-1", RealUsePathStyle: true, RoutingTokenKey: testRoutingTokenKey}, nil
	}
	return resolver
}

func TestConnectionCannotRemoveAuthorizedHeaders(t *testing.T) {
	for _, header := range []string{"x-amz-server-side-encryption", "x-amz-acl", "x-amz-tagging", "x-amz-checksum-sha256", "content-type", "content-length", "authorization", "host"} {
		t.Run(header, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "http://example.com/bucket/key", nil)
			req.Header.Set("Connection", "keep-alive, "+header)
			_, err := planS3Operation(req, "bucket", "key")
			require.Error(t, err)
		})
	}
	resolver := newTestResolver()
	policy, err := ParseS3IAMPolicyJSON(`{"Statement":{"Effect":"Allow","Action":"s3:PutObject","Resource":"*","Condition":{"StringEquals":{"s3:x-amz-server-side-encryption":"AES256"}}}}`)
	require.NoError(t, err)
	resolver.credentials = func(context.Context, string) (*VirtualCredentials, error) {
		return &VirtualCredentials{SecretKey: testSecretKey, IAMPolicy: policy}, nil
	}
	resolver.vbucket = func(context.Context, string, string) (*VBucketConfig, error) {
		t.Error("rejected header reached mapping lookup")
		return nil, ErrResolverNotFound
	}
	server := httptest.NewServer(NewServer(":0", RegisterS3Routes(resolver)).Handler)
	defer server.Close()
	req := signedRequestWithHeaders(t, http.MethodPut, server.URL+"/bucket/key", []byte("body"), unsignedPayload, validCreds, map[string]string{"x-amz-server-side-encryption": "AES256", "Connection": "x-amz-server-side-encryption"})
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAdminRoutesDoNotShadowS3Objects(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "object:"+r.URL.Path) }))
	defer origin.Close()
	resolver := boundaryResolverForOrigin(origin.URL)
	resolver.baseHost = func(_ context.Context, host string) (string, bool, error) {
		return "s3.example.com", strings.HasSuffix(host, ".s3.example.com"), nil
	}
	data := httptest.NewServer(NewServer(":0", RegisterS3Routes(resolver)).Handler)
	defer data.Close()
	readiness := &mutableReadiness{snapshot: ReadinessSnapshot{Ready: true, State: "ready"}}
	admin := httptest.NewServer(NewAdminServer(":0", readiness).Handler)
	defer admin.Close()
	for _, key := range []string{"hc", "ready"} {
		// Signing the virtual host while dialing the local listener preserves SigV4.
		req := signedRequest(t, http.MethodGet, "http://bucket.s3.example.com/"+key, nil, unsignedPayload, validCreds)
		req.Host = req.URL.Host
		target := strings.TrimPrefix(data.URL, "http://")
		req.URL.Host = target
		resp, err := data.Client().Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, "object:/real-bucket/"+key, string(body))
		resp, err = admin.Client().Get(admin.URL + "/" + key)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}
	readiness.set(ReadinessSnapshot{State: "disconnected"})
	resp, err := admin.Client().Get(admin.URL + "/ready")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

type unreadBody struct{ reads int }

func (b *unreadBody) Read([]byte) (int, error) {
	b.reads++
	return 0, errors.New("body must not be read")
}
func (*unreadBody) Close() error { return nil }

func TestUnauthenticatedH2CUpgradeDoesNotReadBody(t *testing.T) {
	body := &unreadBody{}
	req := httptest.NewRequest(http.MethodPut, "http://example.com/bucket/key", body)
	req.Header.Set("Connection", "Upgrade, HTTP2-Settings")
	req.Header.Set("Upgrade", "h2c")
	req.Header.Set("HTTP2-Settings", "")
	rec := httptest.NewRecorder()
	NewServer(":0", RegisterS3Routes(newTestResolver())).Handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Zero(t, body.reads, "upgrade handling must not buffer before authentication")
}

func TestFailedStreamingResponseAbortsClientTransfer(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, kind := range []string{"object", "list-broken-stream", "list-invalid-xml"} {
			listing := kind != "object"
			t.Run(fmt.Sprintf("http2=%t/%s", h2, kind), func(t *testing.T) {
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if listing {
						_, _ = io.WriteString(w, `<ListBucketResult><Name>real-bucket</Name>`+strings.Repeat(`<Contents><Key>safe-key</Key></Contents>`, 500)+`<Contents><Key>unfinished`)
					} else {
						_, _ = io.WriteString(w, strings.Repeat("x", 8192))
					}
					w.(http.Flusher).Flush()
					if kind != "list-invalid-xml" {
						panic(http.ErrAbortHandler)
					}
				}))
				defer origin.Close()
				proxy := httptest.NewUnstartedServer(NewServer(":0", RegisterS3Routes(boundaryResolverForOrigin(origin.URL))).Handler)
				proxy.EnableHTTP2 = h2
				if h2 {
					proxy.StartTLS()
				} else {
					proxy.Start()
				}
				defer proxy.Close()
				path := "/bucket/key"
				if listing {
					path = "/bucket?list-type=2"
				}
				req := signedRequest(t, http.MethodGet, proxy.URL+path, nil, unsignedPayload, validCreds)
				resp, err := proxy.Client().Do(req)
				if err != nil {
					return
				} // A reset before the client receives headers is also a failed transfer.
				defer resp.Body.Close()
				_, err = io.Copy(io.Discard, resp.Body)
				require.Error(t, err, "an aborted origin must never become clean downstream EOF")
				require.Equal(t, h2, resp.ProtoMajor == 2)
			})
		}
	}
}

func TestSuccessfulLargeObjectStreamsBeforeOriginCompletes(t *testing.T) {
	release := make(chan struct{})
	const total = 32 << 20
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 8192))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.CopyN(w, zeroReader{}, total-8192)
	}))
	defer origin.Close()
	proxy := httptest.NewServer(NewServer(":0", RegisterS3Routes(boundaryResolverForOrigin(origin.URL))).Handler)
	defer proxy.Close()
	req := signedRequest(t, http.MethodGet, proxy.URL+"/bucket/key", nil, unsignedPayload, validCreds)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := proxy.Client().Do(req.WithContext(ctx))
	require.NoError(t, err)
	defer resp.Body.Close()
	first := make([]byte, 1024)
	_, err = io.ReadFull(resp.Body, first)
	require.NoError(t, err, "proxy must send bytes before origin body completion")
	close(release)
	n, err := io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.Equal(t, int64(total-len(first)), n)
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestResolverErrorsPreserveHTTPMeaning(t *testing.T) {
	for _, stage := range []string{"credentials", "mapping", "base-host", "create", "list", "begin", "final"} {
		for _, tt := range []struct {
			name   string
			err    error
			status int
			code   string
		}{
			{"not-found", ErrResolverNotFound, 403, "AccessDenied"},
			{"denied", ErrVBucketAccessDenied, 403, "AccessDenied"},
			{"unavailable", ErrResolverUnavailable, 503, "ServiceUnavailable"},
			{"deadline", context.DeadlineExceeded, 503, "ServiceUnavailable"},
			{"admission", ErrResolverThrottled, 503, "SlowDown"},
			{"invalid", ErrResolverInvalidResponse, 502, "InternalError"},
		} {
			t.Run(stage+"/"+tt.name, func(t *testing.T) {
				resolver := newTestResolver()
				wrapped := fmt.Errorf("private diagnostic: %w", tt.err)
				method, path := http.MethodGet, "/bucket/key"
				switch stage {
				case "credentials":
					resolver.credentials = func(context.Context, string) (*VirtualCredentials, error) { return nil, wrapped }
				case "mapping":
					resolver.vbucket = func(context.Context, string, string) (*VBucketConfig, error) { return nil, wrapped }
				case "base-host":
					resolver.baseHost = func(context.Context, string) (string, bool, error) { return "", false, wrapped }
				case "create":
					method, path = http.MethodPut, "/bucket"
					resolver.create = func(context.Context, string, string, string) error { return wrapped }
				case "list":
					path = "/"
					resolver.list = func(context.Context, string) ([]ListedVBucket, error) { return nil, wrapped }
				case "begin":
					resolver.begin = func() (ResolutionStamp, error) { return ResolutionStamp{}, wrapped }
				case "final":
					resolver.validate = func(ResolutionStamp) error { return wrapped }
				}
				req := signedRequest(t, method, "http://example.com"+path, nil, unsignedPayload, validCreds)
				rec := httptest.NewRecorder()
				NewServer(":0", RegisterS3Routes(resolver)).Handler.ServeHTTP(rec, req)
				require.Equal(t, tt.status, rec.Code)
				code := tt.code
				if stage == "credentials" && tt.name == "not-found" {
					code = "InvalidAccessKeyId"
				}
				require.Contains(t, rec.Body.String(), "<Code>"+code+"</Code>")
				require.NotContains(t, rec.Body.String(), "private diagnostic")
			})
		}
	}
}

func TestClientCancellationClosesOriginStream(t *testing.T) {
	canceled := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 8192))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(canceled)
	}))
	defer origin.Close()
	proxy := httptest.NewServer(NewServer(":0", RegisterS3Routes(boundaryResolverForOrigin(origin.URL))).Handler)
	defer proxy.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := signedRequest(t, http.MethodGet, proxy.URL+"/bucket/key", nil, unsignedPayload, validCreds)
	resp, err := proxy.Client().Do(req.WithContext(ctx))
	require.NoError(t, err)
	defer resp.Body.Close()
	cancel()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("origin request survived downstream cancellation")
	}
}
