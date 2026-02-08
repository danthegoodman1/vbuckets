package http_server

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danthegoodman1/vbuckets/env"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
)

var proxyClient = &http.Client{
	// Don't follow redirects -- return them to the caller as-is
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   env.UpstreamDialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       env.UpstreamIdleConnTimeout,
		TLSHandshakeTimeout:   env.UpstreamTLSHandshakeTimeout,
		ExpectContinueTimeout: env.UpstreamExpectContinueTimeout,
		ResponseHeaderTimeout: env.UpstreamResponseHeaderTimeout,
	},
}

func RegisterS3Routes(resolver Resolver) RegisterRoutes {
	return func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(S3Auth(resolver))
			r.HandleFunc("/*", handleS3Request)
		})
	}
}

func handleS3Request(w http.ResponseWriter, r *http.Request) {
	logger := zerolog.Ctx(r.Context())

	vbConfig := getVBucketConfig(r.Context())
	objectKey := getObjectKey(r.Context())

	var normalizedPrefix string
	if vbConfig.PathPrefix != "" {
		normalizedPrefix = strings.TrimSuffix(vbConfig.PathPrefix, "/") + "/"
	}

	listRewrite := normalizedPrefix != "" && isListObjectsRequest(r.Method, objectKey, r.URL.RawQuery)

	// For non-list requests, prepend the prefix to the object key in the path.
	// For list requests, the prefix goes into the query parameters instead.
	if normalizedPrefix != "" && !listRewrite {
		objectKey = normalizedPrefix + objectKey
	}

	rawQuery := r.URL.RawQuery
	if listRewrite {
		rawQuery = rewriteListQueryForPrefix(rawQuery, normalizedPrefix)
	}

	outboundURL := buildOutboundURL(vbConfig, objectKey, rawQuery)

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outboundURL, r.Body)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create outbound request")
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to construct upstream request")
		return
	}
	outReq.ContentLength = r.ContentLength

	copyHeaders(r.Header, outReq.Header)

	endpointHost := parseEndpoint(vbConfig.RealEndpoint).Host
	if vbConfig.RealUsePathStyle {
		outReq.Host = endpointHost
	} else {
		outReq.Host = vbConfig.RealBucket + "." + endpointHost
	}

	outReq.Header.Del("Authorization")
	outReq.Header.Del("X-Amz-Date")
	outReq.Header.Del("x-amz-content-sha256")

	signRequest(outReq, vbConfig.RealAccessKey, vbConfig.RealSecretKey, vbConfig.RealRegion)

	logger.Debug().
		Str("method", outReq.Method).
		Str("url", outReq.URL.String()).
		Str("host", outReq.Host).
		Msg("forwarding request to real S3")

	resp, err := proxyClient.Do(outReq)
	if err != nil {
		logger.Error().Err(err).Msg("upstream request failed")
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Failed to contact upstream S3")
		return
	}
	defer resp.Body.Close()

	// For list responses, rewrite the XML body to strip the path prefix
	// from keys and replace the real bucket name with the virtual one.
	if listRewrite && resp.StatusCode == http.StatusOK {
		copyHeaders(resp.Header, w.Header())
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		if err := rewriteListResponse(resp.Body, w, normalizedPrefix, getBucketName(r.Context())); err != nil {
			logger.Error().Err(err).Msg("failed to rewrite list response")
		}
		return
	}

	copyHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		logger.Error().Err(err).Msg("failed to stream upstream response body")
	}
}

// parseEndpoint parses a RealEndpoint URL. Defaults to https if no scheme is present.
func parseEndpoint(endpoint string) *url.URL {
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	u, _ := url.Parse(endpoint)
	return u
}

// buildOutboundURL constructs the full URL for the real S3 request.
// Uses vhost-style by default (bucket in host), or path-style if configured.
func buildOutboundURL(cfg *VBucketConfig, objectKey string, rawQuery string) string {
	u := parseEndpoint(cfg.RealEndpoint)

	if cfg.RealUsePathStyle {
		u.Path = "/" + cfg.RealBucket
		if objectKey != "" {
			u.Path += "/" + objectKey
		}
	} else {
		u.Host = cfg.RealBucket + "." + u.Host
		u.Path = "/"
		if objectKey != "" {
			u.Path += objectKey
		}
	}

	u.RawQuery = rawQuery
	return u.String()
}

// copyHeaders copies all headers from src to dst, excluding hop-by-hop headers.
func copyHeaders(src, dst http.Header) {
	hopByHop := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailer":             true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
	}

	for key, vals := range src {
		if hopByHop[key] {
			continue
		}
		for _, v := range vals {
			dst.Add(key, v)
		}
	}
}
