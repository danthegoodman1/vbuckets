package http_server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/danthegoodman1/vbuckets/iam"
)

var ErrUnsupportedS3Operation = errors.New("unsupported S3 operation")

var s3AllowedConditionKeys = map[string]bool{
	"s3:prefix":                       true,
	"s3:delimiter":                    true,
	"s3:max-keys":                     true,
	"s3:locationconstraint":           true,
	"s3:authtype":                     true,
	"s3:signatureversion":             true,
	"s3:signatureage":                 true,
	"s3:x-amz-acl":                    true,
	"s3:x-amz-copy-source":            true,
	"s3:x-amz-grant-full-control":     true,
	"s3:x-amz-grant-read":             true,
	"s3:x-amz-grant-read-acp":         true,
	"s3:x-amz-grant-write":            true,
	"s3:x-amz-grant-write-acp":        true,
	"s3:x-amz-metadata-directive":     true,
	"s3:x-amz-server-side-encryption": true,
	"s3:x-amz-storage-class":          true,
	"s3:x-amz-tagging":                true,
	"s3:x-amz-tagging-directive":      true,
	"aws:currenttime":                 true,
	"aws:epochtime":                   true,
	"aws:securetransport":             true,
}

var s3HeaderConditionKeys = map[string]string{
	"x-amz-acl":                    "s3:x-amz-acl",
	"x-amz-copy-source":            "s3:x-amz-copy-source",
	"x-amz-grant-full-control":     "s3:x-amz-grant-full-control",
	"x-amz-grant-read":             "s3:x-amz-grant-read",
	"x-amz-grant-read-acp":         "s3:x-amz-grant-read-acp",
	"x-amz-grant-write":            "s3:x-amz-grant-write",
	"x-amz-grant-write-acp":        "s3:x-amz-grant-write-acp",
	"x-amz-metadata-directive":     "s3:x-amz-metadata-directive",
	"x-amz-server-side-encryption": "s3:x-amz-server-side-encryption",
	"x-amz-storage-class":          "s3:x-amz-storage-class",
	"x-amz-tagging":                "s3:x-amz-tagging",
	"x-amz-tagging-directive":      "s3:x-amz-tagging-directive",
}

func ParseS3IAMPolicyJSON(policyJSON string) (*iam.Policy, error) {
	return iam.ParsePolicyJSON(policyJSON, iam.Options{
		AllowedConditionKeys: s3AllowedConditionKeys,
	})
}

func AuthorizeS3Request(policy *iam.Policy, r *http.Request, authInfo *AuthInfo, bucket, objectKey, locationConstraint string) error {
	checks, err := buildS3IAMRequests(r, bucket, objectKey, locationConstraint, authInfo, time.Now().UTC())
	if err != nil {
		return err
	}
	for _, check := range checks {
		if err := policy.Authorize(check); err != nil {
			return err
		}
	}
	return nil
}

func buildS3IAMRequests(r *http.Request, bucket, objectKey, locationConstraint string, authInfo *AuthInfo, now time.Time) ([]iam.Request, error) {
	checks, err := mapS3IAMChecks(r, bucket, objectKey)
	if err != nil {
		return nil, err
	}
	ctx := buildS3IAMContext(r, authInfo, objectKey, locationConstraint, now)
	for i := range checks {
		checks[i].Context = ctx
	}
	return checks, nil
}

func mapS3IAMChecks(r *http.Request, bucket, objectKey string) ([]iam.Request, error) {
	query := r.URL.Query()
	bucketResource := s3BucketARN(bucket)
	objectResource := s3ObjectARN(bucket, objectKey)

	if bucket == "" && objectKey == "" {
		if r.Method == http.MethodGet && queryHasOnlyIgnoredKeys(query) {
			return []iam.Request{newIAMRequest("s3:ListAllMyBuckets", "*")}, nil
		}
		return nil, unsupportedS3Operation(r)
	}

	if objectKey == "" {
		switch r.Method {
		case http.MethodPut:
			if queryHasOnlyIgnoredKeys(query) {
				return []iam.Request{newIAMRequest("s3:CreateBucket", bucketResource)}, nil
			}
			return nil, unsupportedS3Operation(r)
		case http.MethodGet:
			if hasQueryKey(query, "uploads") {
				return []iam.Request{newIAMRequest("s3:ListBucketMultipartUploads", bucketResource)}, nil
			}
			if isListObjectsRequest(r.Method, objectKey, r.URL.RawQuery) {
				return []iam.Request{newIAMRequest("s3:ListBucket", bucketResource)}, nil
			}
			return nil, unsupportedS3Operation(r)
		case http.MethodHead:
			if queryHasOnlyIgnoredKeys(query) {
				return []iam.Request{newIAMRequest("s3:ListBucket", bucketResource)}, nil
			}
			return nil, unsupportedS3Operation(r)
		default:
			return nil, unsupportedS3Operation(r)
		}
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if hasQueryKey(query, "uploadId") {
			return []iam.Request{newIAMRequest("s3:ListMultipartUploadParts", objectResource)}, nil
		}
		if hasAnyQueryKey(query, "acl", "tagging", "torrent", "legal-hold", "retention", "attributes") {
			return nil, unsupportedS3Operation(r)
		}
		if hasQueryKey(query, "versionId") {
			return []iam.Request{newIAMRequest("s3:GetObjectVersion", objectResource)}, nil
		}
		return []iam.Request{newIAMRequest("s3:GetObject", objectResource)}, nil

	case http.MethodPut:
		if hasQueryKey(query, "tagging") {
			return []iam.Request{newIAMRequest("s3:PutObjectTagging", objectResource)}, nil
		}
		if hasQueryKey(query, "acl") {
			return []iam.Request{newIAMRequest("s3:PutObjectAcl", objectResource)}, nil
		}
		if hasQueryKey(query, "partNumber") && !hasQueryKey(query, "uploadId") {
			return nil, unsupportedS3Operation(r)
		}
		if hasQueryKey(query, "uploadId") && !hasQueryKey(query, "partNumber") {
			return nil, unsupportedS3Operation(r)
		}
		checks := []iam.Request{newIAMRequest("s3:PutObject", objectResource)}
		if requestUsesACLHeaders(r) {
			checks = append(checks, newIAMRequest("s3:PutObjectAcl", objectResource))
		}
		if hasHeader(r, "x-amz-tagging") {
			checks = append(checks, newIAMRequest("s3:PutObjectTagging", objectResource))
		}
		return checks, nil

	case http.MethodDelete:
		if hasQueryKey(query, "uploadId") {
			return []iam.Request{newIAMRequest("s3:AbortMultipartUpload", objectResource)}, nil
		}
		if hasQueryKey(query, "versionId") {
			return []iam.Request{newIAMRequest("s3:DeleteObjectVersion", objectResource)}, nil
		}
		if !queryHasOnlyIgnoredKeys(query) {
			return nil, unsupportedS3Operation(r)
		}
		return []iam.Request{newIAMRequest("s3:DeleteObject", objectResource)}, nil

	case http.MethodPost:
		if hasQueryKey(query, "uploads") || hasQueryKey(query, "uploadId") {
			return []iam.Request{newIAMRequest("s3:PutObject", objectResource)}, nil
		}
		return nil, unsupportedS3Operation(r)

	default:
		return nil, unsupportedS3Operation(r)
	}
}

func buildS3IAMContext(r *http.Request, authInfo *AuthInfo, objectKey, locationConstraint string, now time.Time) iam.Context {
	ctx := iam.Context{
		"s3:authtype":         []string{"REST-HEADER"},
		"s3:signatureversion": []string{"AWS4-HMAC-SHA256"},
		"aws:currenttime":     []string{now.Format(time.RFC3339)},
		"aws:epochtime":       []string{strconv.FormatInt(now.Unix(), 10)},
		"aws:securetransport": []string{strconv.FormatBool(r.TLS != nil)},
	}

	query := r.URL.Query()
	if locationConstraint != "" {
		ctx["s3:locationconstraint"] = []string{locationConstraint}
	}
	if isBucketListLikeRequest(r.Method, objectKey, r.URL.RawQuery) {
		ctx["s3:prefix"] = queryValuesOrDefault(query, "prefix", "")
		if values, ok := query["delimiter"]; ok {
			ctx["s3:delimiter"] = values
		}
		if values, ok := query["max-keys"]; ok {
			ctx["s3:max-keys"] = values
		}
	}

	for header, conditionKey := range s3HeaderConditionKeys {
		if values := r.Header.Values(header); len(values) > 0 {
			ctx[conditionKey] = values
		}
	}

	if authInfo != nil {
		if signedAt, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date")); err == nil {
			age := now.Sub(signedAt.UTC())
			if age < 0 {
				age = 0
			}
			ctx["s3:signatureage"] = []string{strconv.FormatInt(age.Milliseconds(), 10)}
		}
	}

	return ctx
}

func isBucketListLikeRequest(method string, objectKey string, rawQuery string) bool {
	query, _ := url.ParseQuery(rawQuery)
	return method == http.MethodGet && objectKey == "" && (!hasAnyBucketSubresource(query) || hasQueryKey(query, "uploads"))
}

func hasAnyBucketSubresource(query url.Values) bool {
	for key := range query {
		if bucketSubresources[key] {
			return true
		}
	}
	return false
}

func queryValuesOrDefault(query url.Values, key, defaultValue string) []string {
	if values, ok := query[key]; ok {
		return values
	}
	return []string{defaultValue}
}

func newIAMRequest(action, resource string) iam.Request {
	return iam.Request{
		Action:   action,
		Resource: resource,
	}
}

func s3BucketARN(bucket string) string {
	return "arn:aws:s3:::" + bucket
}

func s3ObjectARN(bucket, key string) string {
	return "arn:aws:s3:::" + bucket + "/" + key
}

func hasQueryKey(query url.Values, key string) bool {
	_, ok := query[key]
	return ok
}

func hasAnyQueryKey(query url.Values, keys ...string) bool {
	for _, key := range keys {
		if hasQueryKey(query, key) {
			return true
		}
	}
	return false
}

func queryHasOnlyIgnoredKeys(query url.Values) bool {
	for key := range query {
		if key != "x-id" {
			return false
		}
	}
	return true
}

func requestUsesACLHeaders(r *http.Request) bool {
	if hasHeader(r, "x-amz-acl") {
		return true
	}
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-amz-grant-") {
			return true
		}
	}
	return false
}

func hasHeader(r *http.Request, key string) bool {
	_, ok := r.Header[http.CanonicalHeaderKey(key)]
	return ok
}

func unsupportedS3Operation(r *http.Request) error {
	return fmt.Errorf("%w: %s %s", ErrUnsupportedS3Operation, r.Method, r.URL.RequestURI())
}
