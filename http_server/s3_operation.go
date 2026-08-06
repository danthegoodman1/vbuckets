package http_server

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/danthegoodman1/vbuckets/iam"
)

var ErrMalformedS3Request = errors.New("malformed S3 request")

type S3OperationKind string

const (
	operationListBuckets             S3OperationKind = "ListBuckets"
	operationCreateBucket            S3OperationKind = "CreateBucket"
	operationHeadBucket              S3OperationKind = "HeadBucket"
	operationListObjects             S3OperationKind = "ListObjects"
	operationListObjectsV2           S3OperationKind = "ListObjectsV2"
	operationListMultipartUploads    S3OperationKind = "ListMultipartUploads"
	operationGetObject               S3OperationKind = "GetObject"
	operationHeadObject              S3OperationKind = "HeadObject"
	operationGetObjectVersion        S3OperationKind = "GetObjectVersion"
	operationHeadObjectVersion       S3OperationKind = "HeadObjectVersion"
	operationPutObject               S3OperationKind = "PutObject"
	operationPutObjectACL            S3OperationKind = "PutObjectAcl"
	operationPutObjectTagging        S3OperationKind = "PutObjectTagging"
	operationCopyObject              S3OperationKind = "CopyObject"
	operationDeleteObject            S3OperationKind = "DeleteObject"
	operationDeleteObjectVersion     S3OperationKind = "DeleteObjectVersion"
	operationCreateMultipartUpload   S3OperationKind = "CreateMultipartUpload"
	operationUploadPart              S3OperationKind = "UploadPart"
	operationListParts               S3OperationKind = "ListParts"
	operationCompleteMultipartUpload S3OperationKind = "CompleteMultipartUpload"
	operationAbortMultipartUpload    S3OperationKind = "AbortMultipartUpload"
)

type S3ResponseProfile string

const (
	responseListBuckets          S3ResponseProfile = "R1"
	responseCreateBucket         S3ResponseProfile = "R2"
	responseSafeHeaders          S3ResponseProfile = "R3"
	responseStreamObject         S3ResponseProfile = "R4"
	responseListObjects          S3ResponseProfile = "R5"
	responseListMultipartUploads S3ResponseProfile = "R6"
	responseCreateMultipart      S3ResponseProfile = "R7"
	responseListParts            S3ResponseProfile = "R8"
	responseCompleteMultipart    S3ResponseProfile = "R9"
	responseCopyObject           S3ResponseProfile = "R10"
)

type s3BodyKind int

const (
	bodyEmpty s3BodyKind = iota + 1
	bodyStreaming
	bodyCreateBucketConfiguration
	bodyCompleteMultipartXML
)

// S3OperationPlan is the single decoded meaning of an accepted client
// request. Its fields are private and populated only by planS3Operation so IAM
// and proxy routing cannot independently reinterpret the wire shape.
type S3OperationPlan struct {
	kind               S3OperationKind
	bucket             string
	objectKey          string
	rawQuery           string
	responseProfile    S3ResponseProfile
	iamChecks          []iam.Request
	copySource         *copySource
	isVHost            bool
	locationConstraint string
	bodyKind           s3BodyKind
	controlBody        []byte
	method             string
	contentLength      int64
	forwardHeaders     http.Header
	query              url.Values
	secureTransport    bool
	signedAt           string
	iamContext         iam.Context
	authorizationReady bool
}

func (p *S3OperationPlan) clone() *S3OperationPlan {
	copyPlan := *p
	copyPlan.iamChecks = append([]iam.Request(nil), p.iamChecks...)
	copyPlan.forwardHeaders = p.forwardHeaders.Clone()
	copyPlan.query = cloneURLValues(p.query)
	copyPlan.controlBody = append([]byte(nil), p.controlBody...)
	copyPlan.iamContext = cloneIAMContext(p.iamContext)
	if p.copySource != nil {
		copySourceCopy := *p.copySource
		copyPlan.copySource = &copySourceCopy
	}
	return &copyPlan
}

func (p *S3OperationPlan) withRequestMetadata(isVHost bool, locationConstraint string) *S3OperationPlan {
	copyPlan := p.clone()
	copyPlan.isVHost = isVHost
	copyPlan.locationConstraint = locationConstraint
	return copyPlan
}

func (p *S3OperationPlan) Kind() S3OperationKind {
	if p == nil {
		return ""
	}
	return p.kind
}

func (p *S3OperationPlan) ResponseProfile() S3ResponseProfile {
	if p == nil {
		return ""
	}
	return p.responseProfile
}

func planS3Operation(r *http.Request, bucket, objectKey string) (planned *S3OperationPlan, err error) {
	defer func() {
		if err != nil || planned == nil {
			return
		}
		if headerErr := validateHeadersForOperation(r, planned.kind); headerErr != nil {
			planned = nil
			err = unsupportedS3OperationReason(r, "%v", headerErr)
			return
		}
		if queryErr := validateQueryForOperation(planned); queryErr != nil {
			planned = nil
			err = unsupportedS3OperationReason(r, "%v", queryErr)
			return
		}
		planned.bodyKind = bodyKindForOperation(planned.kind)
		if bodyErr := validateBodyForOperation(r, planned.bodyKind); bodyErr != nil {
			planned = nil
			err = unsupportedS3OperationReason(r, "%v", bodyErr)
			return
		}
		planned.method = r.Method
		planned.contentLength = r.ContentLength
		planned.forwardHeaders = canonicalHeaderClone(r.Header)
		planned.secureTransport = r.TLS != nil
		planned.signedAt = firstHeaderValue(planned.forwardHeaders, "x-amz-date")
		planned.iamContext = buildS3IAMWireContext(planned)
	}()

	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, malformedS3Request(r, "invalid query encoding: %v", err)
	}
	for key, values := range query {
		if len(values) != 1 {
			return nil, unsupportedS3OperationReason(r, "query parameter %q must occur exactly once", key)
		}
	}
	if err := validateOperationHeaders(r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedS3Operation, err)
	}

	plan := &S3OperationPlan{bucket: bucket, objectKey: objectKey, rawQuery: r.URL.RawQuery, query: cloneURLValues(query)}
	bucketResource := s3BucketARN(bucket)
	objectResource := s3ObjectARN(bucket, objectKey)

	if bucket == "" && objectKey == "" {
		if r.Method == http.MethodGet && queryMatches(query, "ListBuckets", nil, nil) {
			plan.kind = operationListBuckets
			plan.responseProfile = responseListBuckets
			plan.iamChecks = []iam.Request{newIAMRequest("s3:ListAllMyBuckets", "*")}
			return plan, nil
		}
		return nil, unsupportedS3Operation(r)
	}

	if objectKey == "" {
		switch r.Method {
		case http.MethodPut:
			if queryMatches(query, "CreateBucket", nil, nil) && !isCopyObjectRequest(r) {
				plan.kind = operationCreateBucket
				plan.responseProfile = responseCreateBucket
				plan.iamChecks = []iam.Request{newIAMRequest("s3:CreateBucket", bucketResource)}
				return plan, nil
			}
		case http.MethodHead:
			if queryMatches(query, "HeadBucket", nil, nil) {
				plan.kind = operationHeadBucket
				plan.responseProfile = responseSafeHeaders
				plan.iamChecks = []iam.Request{newIAMRequest("s3:ListBucket", bucketResource)}
				return plan, nil
			}
		case http.MethodGet:
			if queryMatches(query, "ListMultipartUploads", []string{"uploads"}, []string{"delimiter", "encoding-type", "key-marker", "max-uploads", "prefix", "upload-id-marker"}) {
				plan.kind = operationListMultipartUploads
				plan.responseProfile = responseListMultipartUploads
				plan.iamChecks = []iam.Request{newIAMRequest("s3:ListBucketMultipartUploads", bucketResource)}
				return plan, nil
			}
			if queryMatchesWithValue(query, "ListObjectsV2", map[string]string{"list-type": "2"}, []string{"prefix", "delimiter", "continuation-token", "fetch-owner", "max-keys", "encoding-type", "start-after"}) {
				plan.kind = operationListObjectsV2
				plan.responseProfile = responseListObjects
				plan.iamChecks = []iam.Request{newIAMRequest("s3:ListBucket", bucketResource)}
				return plan, nil
			}
			if queryMatches(query, "ListObjects", nil, []string{"prefix", "delimiter", "marker", "max-keys", "encoding-type"}) {
				plan.kind = operationListObjects
				plan.responseProfile = responseListObjects
				plan.iamChecks = []iam.Request{newIAMRequest("s3:ListBucket", bucketResource)}
				return plan, nil
			}
		}
		return nil, unsupportedS3Operation(r)
	}

	switch r.Method {
	case http.MethodGet:
		if queryMatchesNonEmpty(query, "ListParts", []string{"uploadId"}, []string{"max-parts", "part-number-marker"}) {
			plan.kind = operationListParts
			plan.responseProfile = responseListParts
			plan.iamChecks = []iam.Request{newIAMRequest("s3:ListMultipartUploadParts", objectResource)}
			return plan, nil
		}
		allowed := []string{"response-cache-control", "response-content-disposition", "response-content-encoding", "response-content-language", "response-content-type", "response-expires", "partNumber"}
		if queryMatchesNonEmpty(query, "GetObject", []string{"versionId"}, allowed) {
			plan.kind = operationGetObjectVersion
			plan.responseProfile = responseStreamObject
			plan.iamChecks = []iam.Request{newIAMRequest("s3:GetObjectVersion", objectResource)}
			return plan, nil
		}
		if queryMatches(query, "GetObject", nil, allowed) {
			plan.kind = operationGetObject
			plan.responseProfile = responseStreamObject
			plan.iamChecks = []iam.Request{newIAMRequest("s3:GetObject", objectResource)}
			return plan, nil
		}
	case http.MethodHead:
		if queryMatchesNonEmpty(query, "HeadObject", []string{"versionId"}, []string{"partNumber"}) {
			plan.kind = operationHeadObjectVersion
			plan.responseProfile = responseSafeHeaders
			plan.iamChecks = []iam.Request{newIAMRequest("s3:GetObjectVersion", objectResource)}
			return plan, nil
		}
		if queryMatches(query, "HeadObject", nil, []string{"partNumber"}) {
			plan.kind = operationHeadObject
			plan.responseProfile = responseSafeHeaders
			plan.iamChecks = []iam.Request{newIAMRequest("s3:GetObject", objectResource)}
			return plan, nil
		}
	case http.MethodPut:
		if isCopyObjectRequest(r) && queryMatches(query, "CopyObject", nil, nil) {
			source, err := parseCopySource(singleHeaderValue(r, copySourceHeader), bucket)
			if err != nil {
				return nil, unsupportedS3OperationReason(r, "invalid copy source: %v", err)
			}
			plan.kind = operationCopyObject
			plan.responseProfile = responseCopyObject
			plan.copySource = source
			plan.iamChecks = []iam.Request{
				newIAMRequest("s3:PutObject", objectResource),
				newIAMRequest(copySourceAction(source), s3ObjectARN(bucket, source.Key)),
			}
			appendPutHeaderChecks(plan, r, objectResource)
			return plan, nil
		}
		if queryMatches(query, "PutObjectTagging", []string{"tagging"}, nil) && !isCopyObjectRequest(r) {
			plan.kind = operationPutObjectTagging
			plan.responseProfile = responseSafeHeaders
			plan.iamChecks = []iam.Request{newIAMRequest("s3:PutObjectTagging", objectResource)}
			return plan, nil
		}
		if queryMatches(query, "PutObjectAcl", []string{"acl"}, nil) && !isCopyObjectRequest(r) {
			plan.kind = operationPutObjectACL
			plan.responseProfile = responseSafeHeaders
			plan.iamChecks = []iam.Request{newIAMRequest("s3:PutObjectAcl", objectResource)}
			return plan, nil
		}
		if queryMatchesNonEmpty(query, "UploadPart", []string{"partNumber", "uploadId"}, nil) && !isCopyObjectRequest(r) {
			plan.kind = operationUploadPart
			plan.responseProfile = responseSafeHeaders
			plan.iamChecks = []iam.Request{newIAMRequest("s3:PutObject", objectResource)}
			return plan, nil
		}
		if queryMatches(query, "PutObject", nil, nil) && !isCopyObjectRequest(r) {
			plan.kind = operationPutObject
			plan.responseProfile = responseSafeHeaders
			plan.iamChecks = []iam.Request{newIAMRequest("s3:PutObject", objectResource)}
			appendPutHeaderChecks(plan, r, objectResource)
			return plan, nil
		}
	case http.MethodDelete:
		if queryMatchesNonEmpty(query, "AbortMultipartUpload", []string{"uploadId"}, nil) {
			plan.kind = operationAbortMultipartUpload
			plan.responseProfile = responseSafeHeaders
			plan.iamChecks = []iam.Request{newIAMRequest("s3:AbortMultipartUpload", objectResource)}
			return plan, nil
		}
		if queryMatchesNonEmpty(query, "DeleteObject", []string{"versionId"}, nil) {
			plan.kind = operationDeleteObjectVersion
			plan.responseProfile = responseSafeHeaders
			plan.iamChecks = []iam.Request{newIAMRequest("s3:DeleteObjectVersion", objectResource)}
			return plan, nil
		}
		if queryMatches(query, "DeleteObject", nil, nil) {
			plan.kind = operationDeleteObject
			plan.responseProfile = responseSafeHeaders
			plan.iamChecks = []iam.Request{newIAMRequest("s3:DeleteObject", objectResource)}
			return plan, nil
		}
	case http.MethodPost:
		if queryMatches(query, "CreateMultipartUpload", []string{"uploads"}, nil) {
			plan.kind = operationCreateMultipartUpload
			plan.responseProfile = responseCreateMultipart
			plan.iamChecks = []iam.Request{newIAMRequest("s3:PutObject", objectResource)}
			appendPutHeaderChecks(plan, r, objectResource)
			return plan, nil
		}
		if queryMatchesNonEmpty(query, "CompleteMultipartUpload", []string{"uploadId"}, nil) {
			plan.kind = operationCompleteMultipartUpload
			plan.responseProfile = responseCompleteMultipart
			plan.iamChecks = []iam.Request{newIAMRequest("s3:PutObject", objectResource)}
			return plan, nil
		}
	}

	return nil, unsupportedS3Operation(r)
}

func validateQueryForOperation(plan *S3OperationPlan) error {
	if _, ok := plan.query["encoding-type"]; ok && plan.query.Get("encoding-type") != "url" {
		return fmt.Errorf("encoding-type must be url")
	}
	if value, ok := plan.query["fetch-owner"]; ok && value[0] != "true" && value[0] != "false" {
		return fmt.Errorf("fetch-owner must be true or false")
	}
	for _, field := range []struct {
		name     string
		min, max int
	}{
		{name: "max-keys", min: 0, max: 1000},
		{name: "max-uploads", min: 0, max: 1000},
		{name: "max-parts", min: 0, max: 1000},
		{name: "part-number-marker", min: 0, max: 10000},
	} {
		if err := validateOptionalInteger(plan.query, field.name, field.min, field.max); err != nil {
			return err
		}
	}
	if _, ok := plan.query["partNumber"]; ok {
		if err := validateOptionalInteger(plan.query, "partNumber", 1, 10000); err != nil {
			return err
		}
	}
	return nil
}

func validateOptionalInteger(query url.Values, name string, minValue, maxValue int) error {
	values, ok := query[name]
	if !ok {
		return nil
	}
	if len(values) != 1 || values[0] == "" {
		return fmt.Errorf("%s must have exactly one integer value", name)
	}
	value, err := strconv.Atoi(values[0])
	if err != nil || value < minValue || value > maxValue {
		return fmt.Errorf("%s must be an integer from %d through %d", name, minValue, maxValue)
	}
	return nil
}

func queryMatches(query url.Values, xID string, requiredFlags, optional []string) bool {
	required := make(map[string]string, len(requiredFlags))
	for _, key := range requiredFlags {
		required[key] = ""
	}
	return queryMatchesWithValue(query, xID, required, optional)
}

func queryMatchesNonEmpty(query url.Values, xID string, required, optional []string) bool {
	requiredValues := make(map[string]string, len(required))
	for _, key := range required {
		requiredValues[key] = "\x00"
	}
	return queryMatchesWithValue(query, xID, requiredValues, optional)
}

func queryMatchesWithValue(query url.Values, xID string, required map[string]string, optional []string) bool {
	allowed := make(map[string]bool, len(required)+len(optional)+1)
	for key, want := range required {
		values, ok := query[key]
		if !ok || len(values) != 1 {
			return false
		}
		if want == "\x00" {
			if values[0] == "" {
				return false
			}
		} else if values[0] != want {
			return false
		}
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	allowed["x-id"] = true
	for key, values := range query {
		if !allowed[key] || len(values) != 1 {
			return false
		}
		if key == "x-id" && values[0] != xID {
			return false
		}
	}
	return true
}

func validateOperationHeaders(r *http.Request) error {
	singletons := map[string]bool{
		copySourceHeader: true, "x-amz-acl": true, "x-amz-tagging": true,
		"x-amz-storage-class": true, "x-amz-server-side-encryption": true,
		"x-amz-metadata-directive": true, "x-amz-tagging-directive": true,
		"x-amz-sdk-checksum-algorithm": true, "x-amz-checksum-algorithm": true,
		"x-amz-checksum-type":                             true,
		"x-amz-server-side-encryption-customer-algorithm": true,
		"x-amz-server-side-encryption-customer-key":       true,
		"x-amz-server-side-encryption-customer-key-md5":   true,
	}
	for name := range r.Header {
		lower := strings.ToLower(name)
		if knownGrantHeader(lower) || strings.HasPrefix(lower, "x-amz-meta-") || knownChecksumValueHeader(lower) {
			singletons[lower] = true
		}
		if strings.HasPrefix(lower, "x-amz-object-lock-") || strings.HasPrefix(lower, "x-amz-server-side-encryption-aws-kms-") || lower == "x-amz-server-side-encryption-context" || lower == "x-amz-server-side-encryption-bucket-key-enabled" {
			return fmt.Errorf("header %q is not supported", lower)
		}
	}
	for header := range singletons {
		values := allHeaderValues(r.Header, header)
		if len(values) > 1 {
			return fmt.Errorf("header %q must occur at most once", header)
		}
		if len(values) == 1 && strings.TrimSpace(values[0]) == "" {
			return fmt.Errorf("header %q must not be empty", header)
		}
	}
	if value := firstHeaderValue(r.Header, "x-amz-server-side-encryption"); value != "" && value != "AES256" {
		return fmt.Errorf("server-side encryption mode %q is not supported", value)
	}
	if value := firstHeaderValue(r.Header, "x-amz-acl"); value != "" && !validCannedACL(value) {
		return fmt.Errorf("unsupported canned ACL %q", value)
	}
	if err := validateACLHeaderCombination(r.Header); err != nil {
		return err
	}
	if err := validateSSECustomerHeaders(r.Header); err != nil {
		return err
	}
	if err := validateChecksumHeaders(r.Header); err != nil {
		return err
	}
	for _, directive := range []string{"x-amz-metadata-directive", "x-amz-tagging-directive"} {
		if value := firstHeaderValue(r.Header, directive); value != "" && value != "COPY" && value != "REPLACE" {
			return fmt.Errorf("header %q must be COPY or REPLACE", directive)
		}
	}
	return nil
}

func validateHeadersForOperation(r *http.Request, kind S3OperationKind) error {
	allowPutHeaders := kind == operationPutObject || kind == operationCopyObject || kind == operationCreateMultipartUpload
	allowACL := allowPutHeaders || kind == operationPutObjectACL
	if err := validateChecksumHeadersForOperation(r.Header, kind); err != nil {
		return err
	}
	for name := range r.Header {
		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, "x-amz-") {
			continue
		}
		switch {
		case lower == "x-amz-content-sha256", lower == "x-amz-date":
			continue
		case lower == copySourceHeader && kind == operationCopyObject:
			continue
		case (lower == "x-amz-acl" || knownGrantHeader(lower)) && allowACL:
			continue
		case lower == "x-amz-tagging" && allowPutHeaders:
			continue
		case (lower == "x-amz-tagging-directive" || lower == "x-amz-metadata-directive") && kind == operationCopyObject:
			continue
		case (strings.HasPrefix(lower, "x-amz-meta-") || lower == "x-amz-storage-class" || knownSSEHeader(lower)) && allowPutHeaders:
			continue
		case knownChecksumHeader(lower) && checksumHeaderAllowed(kind, lower):
			continue
		default:
			return fmt.Errorf("header %q is not valid for %s", lower, kind)
		}
	}
	return nil
}

func validateChecksumHeadersForOperation(headers http.Header, kind S3OperationKind) error {
	if firstHeaderValue(headers, "x-amz-sdk-checksum-algorithm") != "" {
		hasValue := false
		for name := range checksumValueAlgorithms {
			hasValue = hasValue || firstHeaderValue(headers, name) != ""
		}
		if !hasValue {
			return fmt.Errorf("x-amz-sdk-checksum-algorithm requires a concrete checksum value header")
		}
	}
	return nil
}

func checksumHeaderAllowed(kind S3OperationKind, name string) bool {
	switch {
	case name == "x-amz-sdk-checksum-algorithm":
		return kind == operationPutObject || kind == operationUploadPart
	case name == "x-amz-checksum-algorithm":
		return kind == operationCreateMultipartUpload
	case name == "x-amz-checksum-type":
		return kind == operationCreateMultipartUpload || kind == operationCompleteMultipartUpload
	case knownChecksumValueHeader(name):
		return kind == operationPutObject || kind == operationUploadPart || kind == operationCompleteMultipartUpload
	default:
		return false
	}
}

func bodyKindForOperation(kind S3OperationKind) s3BodyKind {
	switch kind {
	case operationPutObject, operationPutObjectACL, operationPutObjectTagging, operationUploadPart:
		return bodyStreaming
	case operationCreateBucket:
		return bodyCreateBucketConfiguration
	case operationCompleteMultipartUpload:
		return bodyCompleteMultipartXML
	default:
		return bodyEmpty
	}
}

func validateBodyForOperation(r *http.Request, kind s3BodyKind) error {
	if kind != bodyEmpty {
		return nil
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		return fmt.Errorf("%s requires an empty body", r.Method)
	}
	return nil
}

const maxCompleteMultipartBytes = 1 << 20

type completeMultipartUploadDocument struct {
	XMLName xml.Name `xml:"CompleteMultipartUpload"`
}

func (p *S3OperationPlan) withCompleteMultipartBody(body io.ReadCloser) (*S3OperationPlan, error) {
	if p.bodyKind != bodyCompleteMultipartXML {
		return p, nil
	}
	if body == nil {
		return nil, fmt.Errorf("CompleteMultipartUpload body is required")
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, maxCompleteMultipartBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCompleteMultipartBytes {
		return nil, fmt.Errorf("CompleteMultipartUpload body is too large")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("CompleteMultipartUpload body is required")
	}
	var document completeMultipartUploadDocument
	if err := xml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if document.XMLName.Local != "CompleteMultipartUpload" {
		return nil, fmt.Errorf("unexpected CompleteMultipartUpload root %q", document.XMLName.Local)
	}
	copyPlan := p.clone()
	copyPlan.controlBody = append([]byte(nil), data...)
	copyPlan.contentLength = int64(len(data))
	return copyPlan, nil
}

func validateACLHeaderCombination(headers http.Header) error {
	if firstHeaderValue(headers, "x-amz-acl") == "" {
		return nil
	}
	for name := range headers {
		if strings.HasPrefix(strings.ToLower(name), "x-amz-grant-") {
			return fmt.Errorf("x-amz-acl cannot be combined with x-amz-grant-* headers")
		}
	}
	return nil
}

func validateSSECustomerHeaders(headers http.Header) error {
	names := []string{
		"x-amz-server-side-encryption-customer-algorithm",
		"x-amz-server-side-encryption-customer-key",
		"x-amz-server-side-encryption-customer-key-md5",
	}
	present := 0
	for _, name := range names {
		if firstHeaderValue(headers, name) != "" {
			present++
		}
	}
	if present == 0 {
		return nil
	}
	if present != len(names) {
		return fmt.Errorf("SSE-C requires algorithm, key, and key MD5 headers")
	}
	if firstHeaderValue(headers, names[0]) != "AES256" {
		return fmt.Errorf("SSE-C algorithm must be AES256")
	}
	if firstHeaderValue(headers, "x-amz-server-side-encryption") != "" {
		return fmt.Errorf("SSE-S3 and SSE-C headers cannot be combined")
	}
	return nil
}

var checksumValueAlgorithms = map[string]string{
	"x-amz-checksum-crc32":     "CRC32",
	"x-amz-checksum-crc32c":    "CRC32C",
	"x-amz-checksum-crc64nvme": "CRC64NVME",
	"x-amz-checksum-sha1":      "SHA1",
	"x-amz-checksum-sha256":    "SHA256",
}

func validateChecksumHeaders(headers http.Header) error {
	algorithm := ""
	for _, name := range []string{"x-amz-sdk-checksum-algorithm", "x-amz-checksum-algorithm"} {
		value := firstHeaderValue(headers, name)
		if value == "" {
			continue
		}
		if !validChecksumAlgorithm(value) {
			return fmt.Errorf("unsupported checksum algorithm %q", value)
		}
		if algorithm != "" && algorithm != value {
			return fmt.Errorf("checksum algorithm headers conflict")
		}
		algorithm = value
	}
	valueAlgorithm := ""
	for name, candidate := range checksumValueAlgorithms {
		if firstHeaderValue(headers, name) == "" {
			continue
		}
		if valueAlgorithm != "" {
			return fmt.Errorf("only one checksum value header is supported")
		}
		valueAlgorithm = candidate
	}
	if algorithm != "" && valueAlgorithm != "" && algorithm != valueAlgorithm {
		return fmt.Errorf("checksum algorithm does not match checksum value header")
	}
	if value := firstHeaderValue(headers, "x-amz-checksum-type"); value != "" && value != "COMPOSITE" && value != "FULL_OBJECT" {
		return fmt.Errorf("unsupported checksum type %q", value)
	}
	return nil
}

func validChecksumAlgorithm(value string) bool {
	for _, candidate := range checksumValueAlgorithms {
		if value == candidate {
			return true
		}
	}
	return false
}

func knownChecksumValueHeader(name string) bool {
	_, ok := checksumValueAlgorithms[name]
	return ok
}

func knownChecksumHeader(name string) bool {
	return knownChecksumValueHeader(name) || name == "x-amz-sdk-checksum-algorithm" || name == "x-amz-checksum-algorithm" || name == "x-amz-checksum-type"
}

func knownSSEHeader(name string) bool {
	return name == "x-amz-server-side-encryption" || name == "x-amz-server-side-encryption-customer-algorithm" || name == "x-amz-server-side-encryption-customer-key" || name == "x-amz-server-side-encryption-customer-key-md5"
}

func knownGrantHeader(name string) bool {
	switch name {
	case "x-amz-grant-full-control", "x-amz-grant-read", "x-amz-grant-read-acp", "x-amz-grant-write", "x-amz-grant-write-acp":
		return true
	default:
		return false
	}
}

func validCannedACL(value string) bool {
	switch value {
	case "private", "public-read", "public-read-write", "authenticated-read", "aws-exec-read", "bucket-owner-read", "bucket-owner-full-control", "log-delivery-write":
		return true
	default:
		return false
	}
}

func canonicalHeaderClone(headers http.Header) http.Header {
	clone := make(http.Header, len(headers))
	for name, values := range headers {
		canonical := http.CanonicalHeaderKey(name)
		clone[canonical] = append(clone[canonical], values...)
	}
	return clone
}

func allHeaderValues(headers http.Header, name string) []string {
	var values []string
	for candidate, candidateValues := range headers {
		if strings.EqualFold(candidate, name) {
			values = append(values, candidateValues...)
		}
	}
	return values
}

func firstHeaderValue(headers http.Header, name string) string {
	values := allHeaderValues(headers, name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func cloneURLValues(values url.Values) url.Values {
	clone := make(url.Values, len(values))
	for key, items := range values {
		clone[key] = append([]string(nil), items...)
	}
	return clone
}

func singleHeaderValue(r *http.Request, name string) string {
	values := r.Header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

func appendPutHeaderChecks(plan *S3OperationPlan, r *http.Request, resource string) {
	if requestUsesACLHeaders(r) {
		plan.iamChecks = append(plan.iamChecks, newIAMRequest("s3:PutObjectAcl", resource))
	}
	if hasHeader(r, "x-amz-tagging") {
		plan.iamChecks = append(plan.iamChecks, newIAMRequest("s3:PutObjectTagging", resource))
	}
}

func copySourceAction(source *copySource) string {
	if source.VersionID != "" {
		return "s3:GetObjectVersion"
	}
	return "s3:GetObject"
}

func malformedS3Request(r *http.Request, format string, args ...any) error {
	return fmt.Errorf("%w: %s %s: %s", ErrMalformedS3Request, r.Method, r.URL.RequestURI(), fmt.Sprintf(format, args...))
}

func unsupportedS3OperationReason(r *http.Request, format string, args ...any) error {
	return fmt.Errorf("%w: %s %s: %s", ErrUnsupportedS3Operation, r.Method, r.URL.RequestURI(), fmt.Sprintf(format, args...))
}
