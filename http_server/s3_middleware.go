package http_server

import (
	"context"
	"encoding/xml"
	"net/http"

	"github.com/danthegoodman1/vbuckets/env"
	"github.com/rs/zerolog"
)

type contextKey string

const (
	ctxVBucketConfig contextKey = "vbucketConfig"
	ctxAuthInfo      contextKey = "authInfo"
	ctxBucketName    contextKey = "bucketName"
	ctxObjectKey     contextKey = "objectKey"
	ctxIsVHost       contextKey = "isVHost"
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

// S3Auth is middleware that handles AWS SigV4 verification and virtual bucket
// resolution. On success it stores the resolved VBucketConfig, AuthInfo,
// bucket name, object key, and buffered body in the request context.
//
// The ordering is intentional: credentials are looked up and the signature is
// verified before any bucket resolution or config lookup. This keeps the two
// concerns independent so they can be cached with different strategies later.
func S3Auth(next http.Handler) http.Handler {
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

		virtualCreds, err := lookupCredentials(authInfo.AccessKeyID)
		if err != nil {
			logger.Warn().Err(err).Str("accessKeyID", authInfo.AccessKeyID).Msg("credential lookup failed")
			writeS3Error(w, http.StatusForbidden, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.")
			return
		}

		if err := verifySignature(r, authInfo, virtualCreds.SecretKey); err != nil {
			logger.Warn().Err(err).Msg("signature verification failed")
			writeS3Error(w, http.StatusForbidden, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided.")
			return
		}

		// --- Phase 2: resolve bucket and authorize the action ---

		bucket, objectKey, isVHost := resolveBucket(r, env.S3BaseHost)
		if bucket == "" {
			writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "Could not determine bucket name")
			return
		}

		vbConfig, err := lookupVBucket(authInfo.AccessKeyID, bucket)
		if err != nil {
			logger.Warn().Err(err).Str("accessKeyID", authInfo.AccessKeyID).Str("bucket", bucket).Msg("vbucket lookup failed")
			writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}

		action := s3ActionFromRequest(r.Method)
		if err := checkIAMPermissions(authInfo.AccessKeyID, bucket, objectKey, action); err != nil {
			logger.Warn().Err(err).Str("action", action).Msg("IAM permission check failed")
			writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, ctxVBucketConfig, vbConfig)
		ctx = context.WithValue(ctx, ctxAuthInfo, authInfo)
		ctx = context.WithValue(ctx, ctxBucketName, bucket)
		ctx = context.WithValue(ctx, ctxObjectKey, objectKey)
		ctx = context.WithValue(ctx, ctxIsVHost, isVHost)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
