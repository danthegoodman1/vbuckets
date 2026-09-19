package http_server

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
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
			Timeout:   env.Current.Upstream.DialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		MaxIdleConns:          env.Current.Upstream.MaxIdleConns,
		MaxIdleConnsPerHost:   env.Current.Upstream.MaxIdleConnsPerHost,
		IdleConnTimeout:       env.Current.Upstream.IdleConnTimeout,
		TLSHandshakeTimeout:   env.Current.Upstream.TLSHandshakeTimeout,
		ExpectContinueTimeout: env.Current.Upstream.ExpectContinueTimeout,
		ResponseHeaderTimeout: env.Current.Upstream.ResponseHeaderTimeout,
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

	if err := resolver.CreateVBucket(r.Context(), authInfo.AccessKeyID, bucket, locationConstraint); err != nil {
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
	logger := zerolog.Ctx(r.Context())
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
	seen := make(map[string]struct{}, len(buckets))
	for _, bucket := range buckets {
		if !isValidBucketName(bucket.Name) {
			logger.Error().Msg("control plane returned an invalid virtual bucket name")
			writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid control-plane bucket listing")
			return
		}
		if bucket.CreationDate.IsZero() {
			logger.Error().Msg("control plane returned a missing virtual bucket creation date")
			writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid control-plane bucket listing")
			return
		}
		if _, duplicate := seen[bucket.Name]; duplicate {
			logger.Error().Msg("control plane returned a duplicate virtual bucket name")
			writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid control-plane bucket listing")
			return
		}
		seen[bucket.Name] = struct{}{}
		result.Buckets.Buckets = append(result.Buckets.Buckets, listBucketEntry{
			Name:         bucket.Name,
			CreationDate: formatS3CreationDate(bucket.CreationDate),
		})
	}

	var payload bytes.Buffer
	if err := xml.NewEncoder(&payload).Encode(result); err != nil {
		logger.Error().Err(err).Msg("failed to encode virtual bucket listing")
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to list buckets")
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(payload.Bytes()); err != nil {
		logger.Warn().Err(err).Msg("client disconnected while writing virtual bucket listing")
	}
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
		writeResolverError(w, err, false)
	}
}

func writeListVBucketsError(w http.ResponseWriter, err error) {
	writeResolverError(w, err, false)
}

func proxyS3Request(w http.ResponseWriter, r *http.Request) {
	logger := zerolog.Ctx(r.Context())

	vbConfig := getVBucketConfig(r.Context())
	plan := getS3OperationPlan(r.Context())
	if plan == nil {
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Missing validated S3 operation plan")
		return
	}
	var err error
	vbConfig, err = NormalizeVBucketConfig(vbConfig)
	if err != nil {
		logger.Error().Err(err).Msg("invalid upstream mapping")
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid upstream S3 mapping")
		return
	}
	objectKey := plan.objectKey
	requestTransform, err := classifyS3RequestTransform(plan.kind)
	if err != nil {
		logger.Error().Err(err).Msg("missing S3 request transform")
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Unsupported upstream request transform")
		return
	}

	var normalizedPrefix string
	if vbConfig.PathPrefix != "" {
		normalizedPrefix = strings.TrimSuffix(vbConfig.PathPrefix, "/") + "/"
	}

	// Bucket operations always stay at the real bucket root. Object operations
	// put the tenant prefix in the path; list operations put it only in the
	// operation's key-bearing query fields.
	if normalizedPrefix != "" && requestTransform == requestTransformObjectPath {
		objectKey = normalizedPrefix + objectKey
	}

	rawQuery, err := rewriteOutboundQuery(plan.kind, plan.rawQuery, normalizedPrefix, requestTransform == requestTransformListQuery, vbConfig)
	if err != nil {
		logger.Warn().Err(err).Msg("invalid virtual continuation token")
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid continuation token")
		return
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

	copyOutboundRequestHeaders(plan.forwardHeaders, outReq.Header, plan.kind)
	if plan.kind == operationCopyObject {
		source := plan.copySource
		versionID := source.VersionID
		if versionID != "" {
			versionID, err = decodeOpaqueToken(vbConfig, "version", versionID)
			if err != nil {
				writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid source version token")
				return
			}
		}
		outReq.Header.Set(copySourceHeader, buildCopySource(vbConfig.RealBucket, normalizedPrefix+source.Key, versionID))
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
		Str("operation", string(plan.kind)).
		Str("host", outReq.Host).
		Bool("pathStyle", vbConfig.RealUsePathStyle).
		Msg("forwarding request to real S3")

	resp, err := proxyClient.Do(outReq)
	if err != nil {
		logger.Error().Err(err).Msg("upstream request failed")
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Failed to contact upstream S3")
		return
	}
	defer resp.Body.Close()

	if err := writeVirtualizedUpstreamResponse(w, r, resp, plan, vbConfig, normalizedPrefix); err != nil {
		logger.Error().Err(err).Msg("failed to virtualize upstream response")
		// Returning normally would turn a failed chunked stream into clean EOF.
		if errors.Is(err, http.ErrAbortHandler) {
			panic(http.ErrAbortHandler)
		}
	}
}

type s3RequestTransform uint8

const (
	requestTransformBucketRoot s3RequestTransform = iota + 1
	requestTransformListQuery
	requestTransformObjectPath
)

func classifyS3RequestTransform(kind S3OperationKind) (s3RequestTransform, error) {
	switch kind {
	case operationListBuckets, operationCreateBucket, operationHeadBucket:
		return requestTransformBucketRoot, nil
	case operationListObjects, operationListObjectsV2, operationListMultipartUploads:
		return requestTransformListQuery, nil
	case operationGetObject, operationHeadObject, operationGetObjectVersion,
		operationHeadObjectVersion, operationPutObject, operationPutObjectACL,
		operationPutObjectTagging, operationCopyObject, operationDeleteObject,
		operationDeleteObjectVersion, operationCreateMultipartUpload,
		operationUploadPart, operationListParts, operationCompleteMultipartUpload,
		operationAbortMultipartUpload:
		return requestTransformObjectPath, nil
	default:
		return 0, fmt.Errorf("no request transform for operation %q", kind)
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

func copyOutboundRequestHeaders(src, dst http.Header, kind S3OperationKind) {
	hopByHop := hopByHopHeaderSet(src)
	for name, values := range src {
		canonical := http.CanonicalHeaderKey(name)
		if hopByHop[canonical] || !safeOutboundRequestHeader(canonical, kind) {
			continue
		}
		for _, value := range values {
			dst.Add(canonical, value)
		}
	}
}

func safeOutboundRequestHeader(name string, kind S3OperationKind) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "x-amz-") {
		// The operation planner has already applied the exact per-operation
		// x-amz-* allowlist before the immutable header snapshot is created.
		return true
	}
	switch name {
	case "Accept", "User-Agent":
		return true
	case "Accept-Encoding":
		return operationReadsObject(kind)
	default:
		return objectReadHeaderAllowed(kind, name) || objectBodyHeaderAllowed(kind, name)
	}
}

func hopByHopHeaderSet(headers http.Header) map[string]bool {
	hopByHop := map[string]bool{
		"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
		"Proxy-Authorization": true, "Te": true, "Trailer": true,
		"Transfer-Encoding": true, "Upgrade": true,
	}
	for _, connection := range headers.Values("Connection") {
		for _, name := range strings.Split(connection, ",") {
			if name = strings.TrimSpace(name); name != "" {
				hopByHop[http.CanonicalHeaderKey(name)] = true
			}
		}
	}
	return hopByHop
}
