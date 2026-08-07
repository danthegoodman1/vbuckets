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
	"time"

	"github.com/danthegoodman1/vbuckets/iam"
	"github.com/rs/zerolog"
)

type contextKey string

const (
	ctxVBucketConfig   contextKey = "vbucketConfig"
	ctxAuthInfo        contextKey = "authInfo"
	ctxS3OperationPlan contextKey = "s3OperationPlan"
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
	plan := getS3OperationPlan(ctx)
	if plan == nil {
		return ""
	}
	return plan.bucket
}

func getObjectKey(ctx context.Context) string {
	plan := getS3OperationPlan(ctx)
	if plan == nil {
		return ""
	}
	return plan.objectKey
}

func getIsVHost(ctx context.Context) bool {
	plan := getS3OperationPlan(ctx)
	return plan != nil && plan.isVHost
}

func getCreateLocationConstraint(ctx context.Context) string {
	plan := getS3OperationPlan(ctx)
	if plan == nil {
		return ""
	}
	return plan.locationConstraint
}

func getS3OperationPlan(ctx context.Context) *S3OperationPlan {
	v, _ := ctx.Value(ctxS3OperationPlan).(*S3OperationPlan)
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

			authHeaders := r.Header.Values("Authorization")
			if len(authHeaders) == 0 || authHeaders[0] == "" {
				writeS3Error(w, http.StatusForbidden, "AccessDenied", "Missing Authorization header")
				return
			}
			if len(authHeaders) != 1 {
				writeS3Error(w, http.StatusBadRequest, "AuthorizationHeaderMalformed", "Authorization header must occur exactly once")
				return
			}

			authInfo, err := parseAuthorizationHeader(authHeaders[0])
			if err != nil {
				// Parser errors may quote attacker-controlled credential material.
				// Keep the precise client response, but never copy it into logs.
				logger.Warn().Msg("failed to parse authorization header")
				writeS3Error(w, http.StatusBadRequest, "AuthorizationHeaderMalformed", err.Error())
				return
			}

			virtualCreds, err := resolver.LookupCredentials(r.Context(), authInfo.AccessKeyID)
			if err != nil {
				logger.Warn().Msg("credential lookup failed")
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
				if errors.Is(err, errUnsupportedPayloadHash) {
					writeS3Error(w, http.StatusBadRequest, "InvalidRequest", "x-amz-content-sha256 must be UNSIGNED-PAYLOAD.")
					return
				}
				if errors.Is(err, errUnsignedAmzHeader) {
					writeS3Error(w, http.StatusForbidden, "AccessDenied", "There were headers present in the request which were not signed.")
					return
				}
				if errors.Is(err, errUnsupportedAuthMode) {
					writeS3Error(w, http.StatusBadRequest, "InvalidRequest", err.Error())
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
			if bucket != "" && !isValidBucketName(bucket) {
				writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "The specified bucket is not valid.")
				return
			}
			plan, err := planS3Operation(r, bucket, objectKey)
			if err != nil {
				logger.Warn().Err(err).Msg("unsupported or malformed S3 request")
				writeS3Error(w, http.StatusBadRequest, "InvalidRequest", "The requested S3 operation or request shape is not supported.")
				return
			}
			plan = plan.withRequestMetadata(isVHost, "")
			if plan.bodyKind == bodyCompleteMultipartXML {
				plan, err = plan.withCompleteMultipartBody(r.Body)
				if err != nil {
					logger.Warn().Err(err).Msg("invalid CompleteMultipartUpload body")
					writeS3Error(w, http.StatusBadRequest, "InvalidRequest", "Invalid CompleteMultipartUpload body.")
					return
				}
			}

			if plan.kind == operationListBuckets {
				plan = plan.withAuthorizationContext("", time.Now().UTC())
				if err := AuthorizeS3Plan(virtualCreds.IAMPolicy, plan); err != nil {
					logger.Warn().Err(err).Msg("IAM permission check failed")
					writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
					return
				}

				ctx := withS3RequestContext(r.Context(), nil, authInfo, plan)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if bucket == "" {
				writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "Could not determine bucket name")
				return
			}

			if plan.kind == operationCreateBucket {
				locationConstraint, err := parseCreateBucketLocationConstraint(r.Body)
				if err != nil {
					logger.Warn().Err(err).Msg("failed to parse CreateBucketConfiguration")
					writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid CreateBucketConfiguration")
					return
				}
				plan = plan.withRequestMetadata(isVHost, locationConstraint)
				plan = plan.withAuthorizationContext(locationConstraint, time.Now().UTC())
				if err := AuthorizeS3Plan(virtualCreds.IAMPolicy, plan); err != nil {
					logger.Warn().Err(err).Msg("IAM permission check failed")
					writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
					return
				}

				ctx := withS3RequestContext(r.Context(), nil, authInfo, plan)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			vbConfig, err := resolver.LookupVBucket(r.Context(), authInfo.AccessKeyID, bucket)
			if err != nil {
				logger.Warn().Msg("vbucket lookup failed")
				writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
				return
			}

			plan = plan.withAuthorizationContext("", time.Now().UTC())
			if err := AuthorizeS3Plan(virtualCreds.IAMPolicy, plan); err != nil {
				logger.Warn().Err(err).Msg("IAM permission check failed")
				writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
				return
			}

			ctx := withS3RequestContext(r.Context(), vbConfig, authInfo, plan)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func withS3RequestContext(ctx context.Context, vbConfig *VBucketConfig, authInfo *AuthInfo, plan *S3OperationPlan) context.Context {
	ctx = context.WithValue(ctx, ctxVBucketConfig, vbConfig)
	ctx = context.WithValue(ctx, ctxAuthInfo, authInfo)
	ctx = context.WithValue(ctx, ctxS3OperationPlan, plan)
	return ctx
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
