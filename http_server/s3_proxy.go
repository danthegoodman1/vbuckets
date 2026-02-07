package http_server

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
)

var proxyClient = &http.Client{
	// Don't follow redirects -- return them to the caller as-is
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Timeout: 5 * time.Minute,
}

func RegisterS3Routes(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(S3Auth)
		r.HandleFunc("/*", handleS3Request)
	})
}

func handleS3Request(w http.ResponseWriter, r *http.Request) {
	logger := zerolog.Ctx(r.Context())

	vbConfig := getVBucketConfig(r.Context())
	objectKey := getObjectKey(r.Context())

	if vbConfig.PathPrefix != "" {
		objectKey = strings.TrimSuffix(vbConfig.PathPrefix, "/") + "/" + objectKey
	}

	outboundURL := buildOutboundURL(vbConfig, objectKey, r)

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outboundURL, r.Body)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create outbound request")
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to construct upstream request")
		return
	}
	outReq.ContentLength = r.ContentLength

	copyHeaders(r.Header, outReq.Header)

	// Set the host to match how we're addressing the real backend
	endpointHost := parseEndpoint(vbConfig.RealEndpoint).Host
	if vbConfig.RealUsePathStyle {
		outReq.Host = endpointHost
	} else {
		outReq.Host = vbConfig.RealBucket + "." + endpointHost
	}

	// Remove the original authorization -- we'll re-sign below
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
func buildOutboundURL(cfg *VBucketConfig, objectKey string, r *http.Request) string {
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

	u.RawQuery = r.URL.RawQuery
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
