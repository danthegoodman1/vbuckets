package http_server

import (
	"bytes"
	"encoding/xml"
	"errors"
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
		MaxIdleConns:          env.UpstreamMaxIdleConns,
		MaxIdleConnsPerHost:   env.UpstreamMaxIdleConnsPerHost,
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
			r.HandleFunc("/*", handleS3Request(resolver))
		})
	}
}

func handleS3Request(resolver Resolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		plan := getS3OperationPlan(r.Context())
		if plan == nil {
			writeS3Error(w, http.StatusInternalServerError, "InternalError", "Missing validated S3 operation plan")
			return
		}
		switch plan.kind {
		case operationCreateBucket:
			handleCreateVBucket(resolver, w, r)
		case operationListBuckets:
			handleListVBuckets(resolver, w, r)
		default:
			proxyS3Request(w, r)
		}
	}
}

func handleCreateVBucket(resolver Resolver, w http.ResponseWriter, r *http.Request) {
	authInfo := getAuthInfo(r.Context())
	bucket := getBucketName(r.Context())
	locationConstraint := getCreateLocationConstraint(r.Context())

	if _, err := resolver.CreateVBucket(r.Context(), authInfo.AccessKeyID, bucket, locationConstraint); err != nil {
		writeCreateVBucketError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Location", "/"+bucket)
	w.WriteHeader(http.StatusOK)
	_ = xml.NewEncoder(w).Encode(createBucketResult{
		Xmlns:    s3XMLNamespace,
		Location: "/" + bucket,
	})
}

func handleListVBuckets(resolver Resolver, w http.ResponseWriter, r *http.Request) {
	authInfo := getAuthInfo(r.Context())
	buckets, err := resolver.ListVBuckets(r.Context(), authInfo.AccessKeyID)
	if err != nil {
		writeListVBucketsError(w, err)
		return
	}

	result := listAllMyBucketsResult{
		Xmlns: s3XMLNamespace,
		Owner: listBucketsOwner{
			ID:          authInfo.AccessKeyID,
			DisplayName: authInfo.AccessKeyID,
		},
	}
	for _, bucket := range buckets {
		result.Buckets.Buckets = append(result.Buckets.Buckets, listBucketEntry{
			Name:         bucket.Name,
			CreationDate: formatS3CreationDate(bucket.CreationDate),
		})
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_ = xml.NewEncoder(w).Encode(result)
}

const s3XMLNamespace = "http://s3.amazonaws.com/doc/2006-03-01/"

type createBucketResult struct {
	XMLName  xml.Name `xml:"CreateBucketResult"`
	Xmlns    string   `xml:"xmlns,attr,omitempty"`
	Location string   `xml:"Location,omitempty"`
}

type listAllMyBucketsResult struct {
	XMLName xml.Name           `xml:"ListAllMyBucketsResult"`
	Xmlns   string             `xml:"xmlns,attr,omitempty"`
	Owner   listBucketsOwner   `xml:"Owner"`
	Buckets listBucketsWrapper `xml:"Buckets"`
}

type listBucketsOwner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type listBucketsWrapper struct {
	Buckets []listBucketEntry `xml:"Bucket"`
}

type listBucketEntry struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

func formatS3CreationDate(t time.Time) string {
	if t.IsZero() {
		t = time.Unix(0, 0).UTC()
	}
	return t.UTC().Format(time.RFC3339)
}

func writeCreateVBucketError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrVBucketAlreadyOwnedByYou):
		writeS3Error(w, http.StatusConflict, "BucketAlreadyOwnedByYou", "Your previous request to create the named bucket succeeded and you already own it.")
	case errors.Is(err, ErrVBucketAlreadyExists):
		writeS3Error(w, http.StatusConflict, "BucketAlreadyExists", "The requested bucket name is not available.")
	case errors.Is(err, ErrInvalidVBucketName):
		writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "The specified bucket is not valid.")
	case errors.Is(err, ErrInvalidVBucketArgument):
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid bucket creation argument.")
	case errors.Is(err, ErrVBucketAccessDenied):
		writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
	default:
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to create bucket")
	}
}

func writeListVBucketsError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrVBucketAccessDenied) {
		writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}
	writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to list buckets")
}

func proxyS3Request(w http.ResponseWriter, r *http.Request) {
	logger := zerolog.Ctx(r.Context())

	vbConfig := getVBucketConfig(r.Context())
	plan := getS3OperationPlan(r.Context())
	if plan == nil {
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Missing validated S3 operation plan")
		return
	}
	objectKey := plan.objectKey

	var normalizedPrefix string
	if vbConfig.PathPrefix != "" {
		normalizedPrefix = strings.TrimSuffix(vbConfig.PathPrefix, "/") + "/"
	}

	listRewrite := normalizedPrefix != "" && (plan.kind == operationListObjects || plan.kind == operationListObjectsV2)

	// For non-list requests, prepend the prefix to the object key in the path.
	// For list requests, the prefix goes into the query parameters instead.
	if normalizedPrefix != "" && !listRewrite {
		objectKey = normalizedPrefix + objectKey
	}

	rawQuery := plan.rawQuery
	if listRewrite {
		rawQuery = rewriteListQueryForPrefix(rawQuery, normalizedPrefix)
	}

	outboundURL := buildOutboundURL(vbConfig, objectKey, rawQuery)

	body := r.Body
	if plan.bodyKind == bodyCompleteMultipartXML {
		body = io.NopCloser(bytes.NewReader(plan.controlBody))
	}
	outReq, err := http.NewRequestWithContext(r.Context(), plan.method, outboundURL, body)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create outbound request")
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to construct upstream request")
		return
	}
	outReq.ContentLength = plan.contentLength

	copyHeaders(plan.forwardHeaders, outReq.Header)
	if plan.kind == operationCopyObject {
		source := plan.copySource
		outReq.Header.Set(copySourceHeader, buildCopySource(vbConfig.RealBucket, normalizedPrefix+source.Key, source.VersionID))
	}

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
		if err := rewriteListResponse(resp.Body, w, normalizedPrefix, plan.bucket, listResponseUsesURLEncoding(plan.rawQuery)); err != nil {
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
