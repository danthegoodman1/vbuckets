package http_server

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/danthegoodman1/vbuckets/iam"
	"github.com/rs/zerolog"
)

type contextKey string
type s3Operation string

const (
	ctxVBucketConfig            contextKey = "vbucketConfig"
	ctxAuthInfo                 contextKey = "authInfo"
	ctxBucketName               contextKey = "bucketName"
	ctxObjectKey                contextKey = "objectKey"
	ctxIsVHost                  contextKey = "isVHost"
	ctxS3Operation              contextKey = "s3Operation"
	ctxCreateLocationConstraint contextKey = "createLocationConstraint"
)

const (
	s3OperationProxy        s3Operation = "proxy"
	s3OperationCreateBucket s3Operation = "createBucket"
	s3OperationListBuckets  s3Operation = "listBuckets"
)

func getVBucketConfig(ctx context.Context) *VBucketConfig {
	v, _ := ctx.Value(ctxVBucketConfig).(*VBucketConfig)
	return v
}

func getAuthInfo(ctx context.Context) *AuthInfo {
	v, _ := ctx.Value(ctxAuthInfo).(*AuthInfo)
	return v
}

func getBucketName(ctx context.Context) string {
	v, _ := ctx.Value(ctxBucketName).(string)
	return v
}

func getObjectKey(ctx context.Context) string {
	v, _ := ctx.Value(ctxObjectKey).(string)
	return v
}

func getIsVHost(ctx context.Context) bool {
	v, _ := ctx.Value(ctxIsVHost).(bool)
	return v
}

func getS3Operation(ctx context.Context) s3Operation {
	v, _ := ctx.Value(ctxS3Operation).(s3Operation)
	if v == "" {
		return s3OperationProxy
	}
	return v
}

func getCreateLocationConstraint(ctx context.Context) string {
	v, _ := ctx.Value(ctxCreateLocationConstraint).(string)
	return v
}

// S3Auth returns middleware that handles AWS SigV4 verification and virtual
// bucket resolution. On success it stores the resolved VBucketConfig, AuthInfo,
// bucket name, object key, and buffered body in the request context.
//
// The ordering is intentional: credentials are looked up and the signature is
// verified before any bucket resolution or config lookup. This keeps the two
// concerns independent so they can be cached with different strategies later.
func S3Auth(resolver Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := zerolog.Ctx(r.Context())

			// --- Phase 1: authenticate the request ---

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeS3Error(w, http.StatusForbidden, "AccessDenied", "Missing Authorization header")
				return
			}

			authInfo, err := parseAuthorizationHeader(authHeader)
			if err != nil {
				logger.Warn().Err(err).Msg("failed to parse authorization header")
				writeS3Error(w, http.StatusBadRequest, "AuthorizationHeaderMalformed", err.Error())
				return
			}

			virtualCreds, err := resolver.LookupCredentials(r.Context(), authInfo.AccessKeyID)
			if err != nil {
				logger.Warn().Err(err).Str("accessKeyID", authInfo.AccessKeyID).Msg("credential lookup failed")
				if errors.Is(err, iam.ErrInvalidPolicy) {
					writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
					return
				}
				writeS3Error(w, http.StatusForbidden, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.")
				return
			}

			if err := verifySignature(r, authInfo, virtualCreds.SecretKey); err != nil {
				logger.Warn().Err(err).Msg("signature verification failed")
				if errors.Is(err, errRequestTimeTooSkewed) {
					writeS3Error(w, http.StatusForbidden, "RequestTimeTooSkewed", "The difference between the request time and server time is too large.")
					return
				}
				writeS3Error(w, http.StatusForbidden, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided.")
				return
			}

			// --- Phase 2: resolve bucket and authorize the action ---

			bucket, objectKey, isVHost, err := resolveBucket(resolver, r)
			if err != nil {
				logger.Warn().Err(err).Msg("bucket resolution failed")
				writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to resolve bucket")
				return
			}
			if isListBucketsRequest(r, bucket, objectKey) {
				if err := AuthorizeS3Request(virtualCreds.IAMPolicy, r, authInfo, "", "", ""); err != nil {
					logger.Warn().Err(err).Msg("IAM permission check failed")
					writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
					return
				}

				ctx := withS3RequestContext(r.Context(), nil, authInfo, "", "", isVHost, s3OperationListBuckets, "")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if bucket == "" {
				writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "Could not determine bucket name")
				return
			}

			if isCreateBucketRequest(r, objectKey) {
				if !isValidBucketName(bucket) {
					writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "The specified bucket is not valid.")
					return
				}
				locationConstraint, err := parseCreateBucketLocationConstraint(r.Body)
				if err != nil {
					logger.Warn().Err(err).Msg("failed to parse CreateBucketConfiguration")
					writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid CreateBucketConfiguration")
					return
				}
				if err := AuthorizeS3Request(virtualCreds.IAMPolicy, r, authInfo, bucket, objectKey, locationConstraint); err != nil {
					logger.Warn().Err(err).Msg("IAM permission check failed")
					writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
					return
				}

				ctx := withS3RequestContext(r.Context(), nil, authInfo, bucket, objectKey, isVHost, s3OperationCreateBucket, locationConstraint)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			vbConfig, err := resolver.LookupVBucket(r.Context(), authInfo.AccessKeyID, bucket)
			if err != nil {
				logger.Warn().Err(err).Str("accessKeyID", authInfo.AccessKeyID).Str("bucket", bucket).Msg("vbucket lookup failed")
				writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
				return
			}

			if err := AuthorizeS3Request(virtualCreds.IAMPolicy, r, authInfo, bucket, objectKey, ""); err != nil {
				logger.Warn().Err(err).Msg("IAM permission check failed")
				writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
				return
			}

			ctx := withS3RequestContext(r.Context(), vbConfig, authInfo, bucket, objectKey, isVHost, s3OperationProxy, "")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func withS3RequestContext(ctx context.Context, vbConfig *VBucketConfig, authInfo *AuthInfo, bucket, objectKey string, isVHost bool, operation s3Operation, locationConstraint string) context.Context {
	ctx = context.WithValue(ctx, ctxVBucketConfig, vbConfig)
	ctx = context.WithValue(ctx, ctxAuthInfo, authInfo)
	ctx = context.WithValue(ctx, ctxBucketName, bucket)
	ctx = context.WithValue(ctx, ctxObjectKey, objectKey)
	ctx = context.WithValue(ctx, ctxIsVHost, isVHost)
	ctx = context.WithValue(ctx, ctxS3Operation, operation)
	ctx = context.WithValue(ctx, ctxCreateLocationConstraint, locationConstraint)
	return ctx
}

func isListBucketsRequest(r *http.Request, bucket, objectKey string) bool {
	return r.Method == http.MethodGet && bucket == "" && objectKey == "" && queryHasOnlyIgnoredKeys(r.URL.Query())
}

func isCreateBucketRequest(r *http.Request, objectKey string) bool {
	return r.Method == http.MethodPut && objectKey == "" && queryHasOnlyIgnoredKeys(r.URL.Query())
}

const maxCreateBucketConfigBytes = 1 << 20

type createBucketConfiguration struct {
	XMLName            xml.Name `xml:"CreateBucketConfiguration"`
	LocationConstraint string   `xml:"LocationConstraint"`
}

func parseCreateBucketLocationConstraint(body io.ReadCloser) (string, error) {
	if body == nil {
		return "", nil
	}
	defer body.Close()

	data, err := io.ReadAll(io.LimitReader(body, maxCreateBucketConfigBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxCreateBucketConfigBytes {
		return "", fmt.Errorf("CreateBucketConfiguration is too large")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return "", nil
	}

	var cfg createBucketConfiguration
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return "", err
	}
	if cfg.XMLName.Local != "CreateBucketConfiguration" {
		return "", fmt.Errorf("unexpected CreateBucketConfiguration root %q", cfg.XMLName.Local)
	}
	return strings.TrimSpace(cfg.LocationConstraint), nil
}

var bucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func isValidBucketName(bucket string) bool {
	if !bucketNamePattern.MatchString(bucket) {
		return false
	}
	if strings.Contains(bucket, "..") || strings.Contains(bucket, ".-") || strings.Contains(bucket, "-.") {
		return false
	}
	return true
}

type s3ErrorResponse struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

func writeS3Error(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	xml.NewEncoder(w).Encode(s3ErrorResponse{
		Code:    code,
		Message: message,
	})
}
