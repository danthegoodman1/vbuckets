package http_server

import (
	"errors"
	"fmt"
	"net/http"
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

var s3ConditionKeyTypes = map[string]iam.ConditionValueType{
	"s3:prefix":                       iam.ConditionValueString,
	"s3:delimiter":                    iam.ConditionValueString,
	"s3:max-keys":                     iam.ConditionValueNumeric,
	"s3:locationconstraint":           iam.ConditionValueString,
	"s3:authtype":                     iam.ConditionValueString,
	"s3:signatureversion":             iam.ConditionValueString,
	"s3:signatureage":                 iam.ConditionValueNumeric,
	"s3:x-amz-acl":                    iam.ConditionValueString,
	"s3:x-amz-copy-source":            iam.ConditionValueString,
	"s3:x-amz-grant-full-control":     iam.ConditionValueString,
	"s3:x-amz-grant-read":             iam.ConditionValueString,
	"s3:x-amz-grant-read-acp":         iam.ConditionValueString,
	"s3:x-amz-grant-write":            iam.ConditionValueString,
	"s3:x-amz-grant-write-acp":        iam.ConditionValueString,
	"s3:x-amz-metadata-directive":     iam.ConditionValueString,
	"s3:x-amz-server-side-encryption": iam.ConditionValueString,
	"s3:x-amz-storage-class":          iam.ConditionValueString,
	"s3:x-amz-tagging":                iam.ConditionValueString,
	"s3:x-amz-tagging-directive":      iam.ConditionValueString,
	"aws:currenttime":                 iam.ConditionValueDate,
	"aws:epochtime":                   iam.ConditionValueNumeric,
	"aws:securetransport":             iam.ConditionValueBool,
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
		ConditionKeyTypes:    s3ConditionKeyTypes,
	})
}

func AuthorizeS3Plan(policy *iam.Policy, plan *S3OperationPlan) error {
	if plan == nil || !plan.authorizationReady {
		return fmt.Errorf("%w: operation plan authorization context is not sealed", ErrMalformedS3Request)
	}
	checks := buildS3IAMRequestsFromPlan(plan)
	for _, check := range checks {
		if err := policy.Authorize(check); err != nil {
			return err
		}
	}
	return nil
}

func buildS3IAMRequestsFromPlan(plan *S3OperationPlan) []iam.Request {
	checks := make([]iam.Request, len(plan.iamChecks))
	for i := range plan.iamChecks {
		checks[i] = plan.iamChecks[i]
		checks[i].Context = cloneIAMContext(plan.iamChecks[i].Context)
	}
	return checks
}

func buildS3IAMWireContext(plan *S3OperationPlan) iam.Context {
	ctx := iam.Context{
		"s3:authtype":         []string{"REST-HEADER"},
		"s3:signatureversion": []string{"AWS4-HMAC-SHA256"},
		"aws:securetransport": []string{strconv.FormatBool(plan.secureTransport)},
	}

	if plan.kind == operationListObjects || plan.kind == operationListObjectsV2 || plan.kind == operationListMultipartUploads {
		ctx["s3:prefix"] = queryValuesOrDefault(plan.query, "prefix", "")
		if values, ok := plan.query["delimiter"]; ok {
			ctx["s3:delimiter"] = append([]string(nil), values...)
		}
		if values, ok := plan.query["max-keys"]; ok {
			ctx["s3:max-keys"] = append([]string(nil), values...)
		}
	}

	for header, conditionKey := range s3HeaderConditionKeys {
		if values := allHeaderValues(plan.forwardHeaders, header); len(values) > 0 {
			ctx[conditionKey] = append([]string(nil), values...)
		}
	}
	return ctx
}

func (p *S3OperationPlan) withAuthorizationContext(locationConstraint string, now time.Time) *S3OperationPlan {
	plan := p.clone()
	plan.locationConstraint = locationConstraint
	ctx := cloneIAMContext(plan.iamContext)
	ctx["aws:currenttime"] = []string{now.Format(time.RFC3339)}
	ctx["aws:epochtime"] = []string{strconv.FormatInt(now.Unix(), 10)}
	if locationConstraint != "" {
		ctx["s3:locationconstraint"] = []string{locationConstraint}
	}
	if signedAt, err := time.Parse("20060102T150405Z", plan.signedAt); err == nil {
		age := now.Sub(signedAt.UTC())
		if age < 0 {
			age = 0
		}
		ctx["s3:signatureage"] = []string{strconv.FormatInt(age.Milliseconds(), 10)}
	}
	plan.iamContext = cloneIAMContext(ctx)
	for i := range plan.iamChecks {
		plan.iamChecks[i].Context = cloneIAMContext(ctx)
	}
	plan.authorizationReady = true
	return plan
}

func queryValuesOrDefault(query map[string][]string, key, defaultValue string) []string {
	if values, ok := query[key]; ok {
		return append([]string(nil), values...)
	}
	return []string{defaultValue}
}

func cloneIAMContext(ctx iam.Context) iam.Context {
	if ctx == nil {
		return nil
	}
	clone := make(iam.Context, len(ctx))
	for key, values := range ctx {
		clone[key] = append([]string(nil), values...)
	}
	return clone
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

func requestUsesACLHeaders(r *http.Request) bool {
	if hasHeader(r, "x-amz-acl") {
		return true
	}
	for name := range r.Header {
		if knownGrantHeader(strings.ToLower(name)) {
			return true
		}
	}
	return false
}

func hasHeader(r *http.Request, key string) bool {
	return len(allHeaderValues(r.Header, key)) != 0
}

func unsupportedS3Operation(r *http.Request) error {
	return fmt.Errorf("%w: %s %s", ErrUnsupportedS3Operation, r.Method, r.URL.RequestURI())
}
