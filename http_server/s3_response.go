package http_server

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const maxS3ControlResponseBytes = 1 << 20

var structurallySafeUpstreamErrorCode = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,127}$`)

// Plain schema paths carry no namespace or request-echo semantics. Every field
// that does is declared once in responseFieldRules below, which drives schema
// admission, transforms, echo validation, container handling, and requiredness.
var knownResponsePaths = map[S3ResponseProfile]map[string]bool{
	responseListObjects: responsePathSet("ListBucketResult",
		"KeyCount", "Contents", "Contents/LastModified", "Contents/ETag",
		"Contents/ChecksumAlgorithm", "Contents/ChecksumType", "Contents/Size", "Contents/StorageClass", "CommonPrefixes"),
	responseListMultipartUploads: responsePathSet("ListMultipartUploadsResult",
		"Upload", "Upload/StorageClass", "Upload/Initiated", "Upload/ChecksumAlgorithm", "Upload/ChecksumType", "CommonPrefixes"),
	responseCreateMultipart: responsePathSet("InitiateMultipartUploadResult", "ChecksumAlgorithm", "ChecksumType"),
	responseListParts: responsePathSet("ListPartsResult",
		"StorageClass", "ChecksumAlgorithm", "ChecksumType", "Part", "Part/PartNumber", "Part/LastModified", "Part/ETag", "Part/Size",
		"Part/ChecksumCRC32", "Part/ChecksumCRC32C", "Part/ChecksumCRC64NVME", "Part/ChecksumSHA1", "Part/ChecksumSHA256"),
	responseCompleteMultipart: responsePathSet("CompleteMultipartUploadResult", "ChecksumCRC32", "ChecksumCRC32C", "ChecksumCRC64NVME", "ChecksumSHA1", "ChecksumSHA256", "ChecksumType"),
	responseCopyObject:        responsePathSet("CopyObjectResult", "ChecksumCRC32", "ChecksumCRC32C", "ChecksumCRC64NVME", "ChecksumSHA1", "ChecksumSHA256"),
}

func writeVirtualizedUpstreamResponse(w http.ResponseWriter, r *http.Request, resp *http.Response, plan *S3OperationPlan, cfg *VBucketConfig, pathPrefix string) error {
	if isS3RedirectStatus(resp.StatusCode) {
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Upstream S3 redirect cannot be safely followed")
		return fmt.Errorf("upstream returned unsafe redirect status %d", resp.StatusCode)
	}
	if r.Method == http.MethodHead {
		if err := copySafeResponseHeaders(resp.Header, w.Header(), cfg, plan, resp.StatusCode); err != nil {
			writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid upstream S3 response")
			return err
		}
		w.WriteHeader(resp.StatusCode)
		return nil
	}
	if resp.StatusCode == http.StatusNotModified {
		if err := copySafeResponseHeaders(resp.Header, w.Header(), cfg, plan, resp.StatusCode); err != nil {
			writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid upstream S3 response")
			return err
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		return nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		upstreamCode, valid := validateUpstreamErrorDocument(resp.Body)
		if !valid {
			writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid upstream S3 response")
			return fmt.Errorf("invalid upstream error response")
		}
		if err := copySafeResponseHeaders(resp.Header, w.Header(), cfg, plan, resp.StatusCode); err != nil {
			writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid upstream S3 response")
			return err
		}
		dropTransformedRepresentationHeaders(w.Header(), responseListObjects)
		w.Header().Del("Content-Length")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(resp.StatusCode)
		return xml.NewEncoder(w).Encode(s3ErrorResponse{Code: safeUpstreamErrorCode(plan.kind, resp.StatusCode, upstreamCode), Message: "Upstream S3 request failed"})
	}

	switch plan.responseProfile {
	case responseStreamObject:
		if err := copySafeResponseHeaders(resp.Header, w.Header(), cfg, plan, resp.StatusCode); err != nil {
			writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid upstream S3 response")
			return err
		}
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			return fmt.Errorf("%w: %w", http.ErrAbortHandler, err)
		}
		return nil
	case responseSafeHeaders:
		if err := copySafeResponseHeaders(resp.Header, w.Header(), cfg, plan, resp.StatusCode); err != nil {
			writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid upstream S3 response")
			return err
		}
		dropDiscardedBodyHeaders(w.Header())
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		return nil
	case responseListObjects, responseListMultipartUploads:
		body, err := preflightStreamingXMLRoot(resp.Body, expectedResponseRoot(plan.responseProfile))
		if err != nil {
			writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid upstream S3 response")
			return err
		}
		if err := copySafeResponseHeaders(resp.Header, w.Header(), cfg, plan, resp.StatusCode); err != nil {
			writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid upstream S3 response")
			return err
		}
		dropTransformedRepresentationHeaders(w.Header(), plan.responseProfile)
		w.Header().Del("Content-Length")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(resp.StatusCode)
		if err := rewriteStreamingNamespaceResponse(body, w, plan, cfg, pathPrefix); err != nil {
			return fmt.Errorf("%w: %w", http.ErrAbortHandler, err)
		}
		return nil
	case responseCreateMultipart, responseListParts, responseCompleteMultipart, responseCopyObject:
		data, err := readBoundedControlXML(resp.Body)
		if err != nil {
			w.Header().Del("Content-Length")
			writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid upstream S3 response")
			return err
		}
		transformed, err := rewriteBoundedNamespaceResponse(data, plan, cfg, pathPrefix)
		if err != nil {
			w.Header().Del("Content-Length")
			writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid upstream S3 response")
			return err
		}
		if err := copySafeResponseHeaders(resp.Header, w.Header(), cfg, plan, resp.StatusCode); err != nil {
			writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid upstream S3 response")
			return err
		}
		dropTransformedRepresentationHeaders(w.Header(), plan.responseProfile)
		w.Header().Del("Content-Length")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(resp.StatusCode)
		_, err = w.Write(transformed)
		return err
	default:
		return fmt.Errorf("unsupported response profile %q", plan.responseProfile)
	}
}

func isS3RedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func readBoundedControlXML(in io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(in, maxS3ControlResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxS3ControlResponseBytes {
		return nil, fmt.Errorf("upstream control response exceeds %d bytes", maxS3ControlResponseBytes)
	}
	return data, nil
}

func validateUpstreamErrorDocument(in io.Reader) (string, bool) {
	data, err := readBoundedControlXML(in)
	if err != nil {
		return "", false
	}
	var document struct {
		XMLName xml.Name
		Code    string `xml:"Code"`
	}
	if err := xml.Unmarshal(data, &document); err != nil || document.XMLName.Local != "Error" {
		return "", false
	}
	if document.XMLName.Space != "" && document.XMLName.Space != s3XMLNamespace {
		return "", false
	}
	code := strings.TrimSpace(document.Code)
	if !structurallySafeUpstreamErrorCode.MatchString(code) {
		return "", false
	}
	return code, true
}

func safeUpstreamErrorCode(kind S3OperationKind, status int, upstream string) string {
	allowedByStatus := map[int]map[string]bool{
		http.StatusBadRequest: {
			"EntityTooSmall": true, "InvalidArgument": true, "InvalidPart": true,
			"InvalidPartOrder": true, "InvalidRequest": true, "MalformedXML": true,
		},
		http.StatusForbidden:                    {"AccessDenied": true, "InvalidObjectState": true},
		http.StatusConflict:                     {"BucketNotEmpty": true, "OperationAborted": true},
		http.StatusPreconditionFailed:           {"PreconditionFailed": true},
		http.StatusRequestedRangeNotSatisfiable: {"InvalidRange": true},
		http.StatusTooManyRequests:              {"SlowDown": true},
		http.StatusInternalServerError:          {"InternalError": true},
		http.StatusServiceUnavailable:           {"SlowDown": true, "ServiceUnavailable": true},
	}
	if status == http.StatusNotFound && compatibleNotFoundCode(kind, upstream) {
		return upstream
	}
	if allowedByStatus[status][upstream] {
		return upstream
	}
	return safeErrorCodeForStatus(kind, status)
}

func compatibleNotFoundCode(kind S3OperationKind, code string) bool {
	switch code {
	case "NoSuchBucket":
		return true
	case "NoSuchUpload":
		switch kind {
		case operationUploadPart, operationListParts, operationCompleteMultipartUpload, operationAbortMultipartUpload:
			return true
		}
	case "NoSuchVersion":
		switch kind {
		case operationGetObjectVersion, operationHeadObjectVersion, operationDeleteObjectVersion, operationCopyObject:
			return true
		}
	case "NoSuchKey":
		switch kind {
		case operationGetObject, operationGetObjectVersion, operationHeadObject, operationHeadObjectVersion,
			operationPutObject, operationCopyObject, operationDeleteObject, operationDeleteObjectVersion,
			operationCreateMultipartUpload, operationUploadPart, operationListParts,
			operationCompleteMultipartUpload, operationAbortMultipartUpload:
			return true
		}
	}
	return false
}

func safeErrorCodeForStatus(kind S3OperationKind, status int) string {
	switch status {
	case http.StatusBadRequest:
		return "InvalidRequest"
	case http.StatusForbidden:
		return "AccessDenied"
	case http.StatusNotFound:
		switch kind {
		case operationHeadBucket, operationListObjects, operationListObjectsV2, operationListMultipartUploads:
			return "NoSuchBucket"
		case operationUploadPart, operationListParts, operationCompleteMultipartUpload, operationAbortMultipartUpload:
			return "NoSuchUpload"
		default:
			return "NoSuchKey"
		}
	case http.StatusConflict:
		return "OperationAborted"
	case http.StatusPreconditionFailed:
		return "PreconditionFailed"
	case http.StatusRequestedRangeNotSatisfiable:
		return "InvalidRange"
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return "SlowDown"
	default:
		return "InternalError"
	}
}

func preflightStreamingXMLRoot(in io.Reader, expected string) (io.Reader, error) {
	buffered := bufio.NewReader(in)
	var consumed bytes.Buffer
	decoder := xml.NewDecoder(io.TeeReader(io.LimitReader(buffered, maxS3ControlResponseBytes+1), &consumed))
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if start, ok := token.(xml.StartElement); ok {
			if start.Name.Local != expected {
				return nil, fmt.Errorf("unexpected response root %q", start.Name.Local)
			}
			if start.Name.Space != "" && start.Name.Space != s3XMLNamespace {
				return nil, fmt.Errorf("foreign XML namespace %q is not supported", start.Name.Space)
			}
			return io.MultiReader(bytes.NewReader(consumed.Bytes()), buffered), nil
		}
	}
}

func rewriteBoundedNamespaceResponse(data []byte, plan *S3OperationPlan, cfg *VBucketConfig, pathPrefix string) ([]byte, error) {
	var out bytes.Buffer
	if err := rewriteNamespaceXML(bytes.NewReader(data), &out, plan, cfg, pathPrefix, virtualResponseLocation(plan)); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func rewriteStreamingNamespaceResponse(in io.Reader, out io.Writer, plan *S3OperationPlan, cfg *VBucketConfig, pathPrefix string) error {
	return rewriteNamespaceXML(in, out, plan, cfg, pathPrefix, "")
}

func rewriteNamespaceXML(in io.Reader, out io.Writer, plan *S3OperationPlan, cfg *VBucketConfig, pathPrefix, virtualLocation string) error {
	decoder := xml.NewDecoder(in)
	encoder := xml.NewEncoder(out)
	var stack []string
	root := expectedResponseRoot(plan.responseProfile)
	seenRoot := false
	seenFields := make(map[string]bool)
	var listPartsTruncated *bool
	var listObjectsTruncated *bool
	var listMultipartTruncated *bool
	var emptyNextContinuationToken bool
	var emptyNextUploadIDMarker bool
	var listContentsOwnerSeen []bool

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch typed := token.(type) {
		case xml.StartElement:
			if seenRoot && len(stack) == 0 {
				return fmt.Errorf("multiple top-level XML elements are not supported")
			}
			if typed.Name.Space != "" && typed.Name.Space != s3XMLNamespace {
				return fmt.Errorf("foreign XML namespace %q is not supported", typed.Name.Space)
			}
			if !seenRoot {
				seenRoot = true
				if root != "" && typed.Name.Local != root {
					return fmt.Errorf("unexpected %s response root %q", plan.responseProfile, typed.Name.Local)
				}
			}
			typed.Attr = filterSafeXMLAttributes(typed.Attr, cfg)
			parentPath := strings.Join(stack, "/")
			stack = append(stack, typed.Name.Local)
			path := strings.Join(stack, "/")
			if !knownResponsePath(plan.responseProfile, path) {
				if parentPath != "" && knownResponsePath(plan.responseProfile, parentPath) && !responsePathIsContainer(plan.responseProfile, parentPath) {
					return fmt.Errorf("nested element inside scalar XML path %q", parentPath)
				}
				if err := decoder.Skip(); err != nil {
					return err
				}
				stack = stack[:len(stack)-1]
				continue
			}
			if path == "ListBucketResult/Contents" {
				listContentsOwnerSeen = append(listContentsOwnerSeen, false)
			}
			if path == "ListBucketResult/Contents/Owner" && len(listContentsOwnerSeen) > 0 {
				listContentsOwnerSeen[len(listContentsOwnerSeen)-1] = true
			}
			if err := encoder.EncodeToken(typed); err != nil {
				return err
			}
			rule, hasRule := responseFieldRuleForPath(plan.responseProfile, path)
			if hasRule && rule.identityContainer {
				if err := decoder.Skip(); err != nil {
					return err
				}
				for _, field := range []string{"ID", "DisplayName"} {
					start := xml.StartElement{Name: xml.Name{Local: field}}
					if err := encoder.EncodeToken(start); err != nil {
						return err
					}
					if err := encoder.EncodeToken(xml.CharData(plan.bucket)); err != nil {
						return err
					}
					if err := encoder.EncodeToken(start.End()); err != nil {
						return err
					}
				}
				if err := encoder.EncodeToken(typed.End()); err != nil {
					return err
				}
				stack = stack[:len(stack)-1]
				continue
			}
			if hasRule && rule.transform != textTransformNone {
				text, end, err := readElementText(decoder, typed)
				if err != nil {
					return err
				}
				text, err = applyResponseTextTransform(rule.transform, path, text, plan, cfg, pathPrefix, virtualLocation)
				if err != nil {
					return err
				}
				if err := encoder.EncodeToken(xml.CharData(text)); err != nil {
					return err
				}
				if err := encoder.EncodeToken(end); err != nil {
					return err
				}
				seenFields[path] = true
				if path == "ListPartsResult/IsTruncated" {
					value, _ := strconv.ParseBool(strings.TrimSpace(text))
					listPartsTruncated = &value
				}
				if path == "ListBucketResult/IsTruncated" {
					value, _ := strconv.ParseBool(strings.TrimSpace(text))
					listObjectsTruncated = &value
				}
				if path == "ListMultipartUploadsResult/IsTruncated" {
					value, _ := strconv.ParseBool(strings.TrimSpace(text))
					listMultipartTruncated = &value
				}
				if path == "ListBucketResult/NextContinuationToken" {
					emptyNextContinuationToken = text == ""
				}
				if path == "ListMultipartUploadsResult/NextUploadIdMarker" {
					emptyNextUploadIDMarker = text == ""
				}
				stack = stack[:len(stack)-1]
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return fmt.Errorf("unbalanced upstream XML")
			}
			path := strings.Join(stack, "/")
			if path == "ListBucketResult/Contents" {
				if len(listContentsOwnerSeen) == 0 {
					return fmt.Errorf("invalid ListObjects owner tracking state")
				}
				ownerSeen := listContentsOwnerSeen[len(listContentsOwnerSeen)-1]
				listContentsOwnerSeen = listContentsOwnerSeen[:len(listContentsOwnerSeen)-1]
				if plan.query.Get("fetch-owner") == "true" && !ownerSeen {
					return fmt.Errorf("ListObjects response omitted Owner requested by fetch-owner")
				}
			}
			stack = stack[:len(stack)-1]
			if err := encoder.EncodeToken(typed); err != nil {
				return err
			}
		case xml.CharData:
			if strings.TrimSpace(string(typed)) != "" {
				path := strings.Join(stack, "/")
				if !knownResponsePath(plan.responseProfile, path) || responsePathIsContainer(plan.responseProfile, path) {
					return fmt.Errorf("unexpected mixed text in upstream XML path %q", path)
				}
			}
			if err := encoder.EncodeToken(typed); err != nil {
				return err
			}
		case xml.Comment, xml.Directive, xml.ProcInst:
			// Upstream comments/directives are non-semantic and could carry backend
			// identifiers outside the schema, so omit them.
		default:
			if err := encoder.EncodeToken(token); err != nil {
				return err
			}
		}
	}
	if !seenRoot || len(stack) != 0 {
		return fmt.Errorf("incomplete upstream XML")
	}
	for path, rule := range responseFieldRules[plan.responseProfile] {
		if rule.required && !seenFields[path] {
			return fmt.Errorf("upstream %s response is missing required field %s", plan.responseProfile, path)
		}
	}
	if plan.responseProfile == responseListParts && listPartsTruncated != nil && *listPartsTruncated && !seenFields["ListPartsResult/NextPartNumberMarker"] {
		return fmt.Errorf("truncated list parts response is missing its next marker")
	}
	if seenFields["ListBucketResult/NextContinuationToken"] && emptyNextContinuationToken && (listObjectsTruncated == nil || *listObjectsTruncated) {
		return fmt.Errorf("empty next continuation token is valid only for a nontruncated response")
	}
	if seenFields["ListMultipartUploadsResult/NextUploadIdMarker"] && emptyNextUploadIDMarker && (listMultipartTruncated == nil || *listMultipartTruncated) {
		return fmt.Errorf("empty next upload ID marker is valid only for a nontruncated response")
	}
	return encoder.Flush()
}

func responsePathIsContainer(profile S3ResponseProfile, path string) bool {
	for candidate := range knownResponsePaths[profile] {
		if strings.HasPrefix(candidate, path+"/") {
			return true
		}
	}
	for candidate, rule := range responseFieldRules[profile] {
		if (candidate == path && rule.identityContainer) || strings.HasPrefix(candidate, path+"/") {
			return true
		}
	}
	return false
}

func readElementText(decoder *xml.Decoder, start xml.StartElement) (string, xml.EndElement, error) {
	var text strings.Builder
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", xml.EndElement{}, err
		}
		switch typed := token.(type) {
		case xml.CharData:
			if text.Len()+len(typed) > maxS3ControlResponseBytes {
				return "", xml.EndElement{}, fmt.Errorf("upstream XML field exceeds %d bytes", maxS3ControlResponseBytes)
			}
			text.Write(typed)
		case xml.Comment, xml.Directive, xml.ProcInst:
			// Non-semantic boundaries are omitted while their surrounding text is
			// accumulated as one value before rewriting.
		case xml.EndElement:
			if typed.Name != start.Name {
				return "", xml.EndElement{}, fmt.Errorf("unexpected XML end element %q", typed.Name.Local)
			}
			return text.String(), typed, nil
		case xml.StartElement:
			return "", xml.EndElement{}, fmt.Errorf("namespace-bearing XML field %q must contain text only", start.Name.Local)
		}
	}
}

func expectedResponseRoot(profile S3ResponseProfile) string {
	switch profile {
	case responseListObjects:
		return "ListBucketResult"
	case responseListMultipartUploads:
		return "ListMultipartUploadsResult"
	case responseCreateMultipart:
		return "InitiateMultipartUploadResult"
	case responseListParts:
		return "ListPartsResult"
	case responseCompleteMultipart:
		return "CompleteMultipartUploadResult"
	case responseCopyObject:
		return "CopyObjectResult"
	default:
		return ""
	}
}

type responseTextTransform uint8

const (
	textTransformNone responseTextTransform = iota
	textTransformVirtualBucket
	textTransformVirtualKey
	textTransformVirtualLocation
	textTransformNewContinuationToken
	textTransformEchoContinuationToken
	textTransformNewUploadToken
	textTransformEchoUploadToken
	textTransformVirtualKeyEcho
	textTransformPlainQueryEcho
	textTransformNumericQueryEcho
	textTransformNonNegativeInteger
	textTransformBoolean
	textTransformRequiredNonempty
)

type responseFieldRule struct {
	transform         responseTextTransform
	required          bool
	identityContainer bool
}

var responseFieldRules = map[S3ResponseProfile]map[string]responseFieldRule{
	responseListObjects: {
		"ListBucketResult/Name":                  {transform: textTransformVirtualBucket},
		"ListBucketResult/Prefix":                {transform: textTransformVirtualKeyEcho},
		"ListBucketResult/StartAfter":            {transform: textTransformVirtualKeyEcho},
		"ListBucketResult/Marker":                {transform: textTransformVirtualKeyEcho},
		"ListBucketResult/NextMarker":            {transform: textTransformVirtualKey},
		"ListBucketResult/CommonPrefixes/Prefix": {transform: textTransformVirtualKey},
		"ListBucketResult/Contents/Key":          {transform: textTransformVirtualKey},
		"ListBucketResult/Delimiter":             {transform: textTransformPlainQueryEcho},
		"ListBucketResult/EncodingType":          {transform: textTransformPlainQueryEcho},
		"ListBucketResult/MaxKeys":               {transform: textTransformNumericQueryEcho},
		"ListBucketResult/IsTruncated":           {transform: textTransformBoolean},
		"ListBucketResult/ContinuationToken":     {transform: textTransformEchoContinuationToken},
		"ListBucketResult/NextContinuationToken": {transform: textTransformNewContinuationToken},
		"ListBucketResult/Contents/Owner":        {identityContainer: true},
	},
	responseListMultipartUploads: {
		"ListMultipartUploadsResult/Bucket":                {transform: textTransformVirtualBucket},
		"ListMultipartUploadsResult/Prefix":                {transform: textTransformVirtualKeyEcho},
		"ListMultipartUploadsResult/KeyMarker":             {transform: textTransformVirtualKeyEcho},
		"ListMultipartUploadsResult/NextKeyMarker":         {transform: textTransformVirtualKey},
		"ListMultipartUploadsResult/CommonPrefixes/Prefix": {transform: textTransformVirtualKey},
		"ListMultipartUploadsResult/Upload/Key":            {transform: textTransformVirtualKey},
		"ListMultipartUploadsResult/Delimiter":             {transform: textTransformPlainQueryEcho},
		"ListMultipartUploadsResult/EncodingType":          {transform: textTransformPlainQueryEcho},
		"ListMultipartUploadsResult/MaxUploads":            {transform: textTransformNumericQueryEcho},
		"ListMultipartUploadsResult/IsTruncated":           {transform: textTransformBoolean},
		"ListMultipartUploadsResult/UploadIdMarker":        {transform: textTransformEchoUploadToken},
		"ListMultipartUploadsResult/NextUploadIdMarker":    {transform: textTransformNewUploadToken},
		"ListMultipartUploadsResult/Upload/UploadId":       {transform: textTransformNewUploadToken},
		"ListMultipartUploadsResult/Upload/Owner":          {identityContainer: true},
		"ListMultipartUploadsResult/Upload/Initiator":      {identityContainer: true},
	},
	responseCreateMultipart: {
		"InitiateMultipartUploadResult/Bucket":   {transform: textTransformVirtualBucket, required: true},
		"InitiateMultipartUploadResult/Key":      {transform: textTransformVirtualKey, required: true},
		"InitiateMultipartUploadResult/UploadId": {transform: textTransformNewUploadToken, required: true},
	},
	responseListParts: {
		"ListPartsResult/Bucket":               {transform: textTransformVirtualBucket, required: true},
		"ListPartsResult/Key":                  {transform: textTransformVirtualKey, required: true},
		"ListPartsResult/UploadId":             {transform: textTransformEchoUploadToken, required: true},
		"ListPartsResult/PartNumberMarker":     {transform: textTransformNumericQueryEcho, required: true},
		"ListPartsResult/NextPartNumberMarker": {transform: textTransformNonNegativeInteger},
		"ListPartsResult/MaxParts":             {transform: textTransformNumericQueryEcho, required: true},
		"ListPartsResult/IsTruncated":          {transform: textTransformBoolean, required: true},
		"ListPartsResult/Owner":                {identityContainer: true},
		"ListPartsResult/Initiator":            {identityContainer: true},
	},
	responseCompleteMultipart: {
		"CompleteMultipartUploadResult/Location": {transform: textTransformVirtualLocation, required: true},
		"CompleteMultipartUploadResult/Bucket":   {transform: textTransformVirtualBucket, required: true},
		"CompleteMultipartUploadResult/Key":      {transform: textTransformVirtualKey, required: true},
		"CompleteMultipartUploadResult/ETag":     {transform: textTransformRequiredNonempty, required: true},
	},
	responseCopyObject: {
		"CopyObjectResult/ETag":         {transform: textTransformRequiredNonempty, required: true},
		"CopyObjectResult/LastModified": {transform: textTransformRequiredNonempty, required: true},
	},
}

func responseFieldRuleForPath(profile S3ResponseProfile, path string) (responseFieldRule, bool) {
	rule, ok := responseFieldRules[profile][path]
	return rule, ok
}

func applyResponseTextTransform(transform responseTextTransform, path, text string, plan *S3OperationPlan, cfg *VBucketConfig, pathPrefix, virtualLocation string) (string, error) {
	switch transform {
	case textTransformVirtualBucket:
		if strings.TrimSpace(text) != cfg.RealBucket {
			return "", fmt.Errorf("upstream bucket %q does not match configured bucket", strings.TrimSpace(text))
		}
		return plan.bucket, nil
	case textTransformVirtualKey:
		return virtualizeResponseKey(path, text, plan, pathPrefix)
	case textTransformVirtualLocation:
		if strings.TrimSpace(text) == "" {
			return "", fmt.Errorf("upstream Location is required")
		}
		return virtualLocation, nil
	case textTransformNewContinuationToken:
		if text == "" && path == "ListBucketResult/NextContinuationToken" {
			return "", nil
		}
		return encodeOpaqueToken(cfg, "continuation", text)
	case textTransformEchoContinuationToken:
		virtual := plan.query.Get("continuation-token")
		if virtual == "" {
			if text == "" && path == "ListBucketResult/ContinuationToken" {
				return "", nil
			}
			return "", fmt.Errorf("upstream echoed a continuation token that was not requested")
		}
		origin, err := decodeOpaqueToken(cfg, "continuation", virtual)
		if err != nil || text != origin {
			return "", fmt.Errorf("upstream continuation token echo does not match request")
		}
		return virtual, nil
	case textTransformNewUploadToken:
		if text == "" && path == "ListMultipartUploadsResult/NextUploadIdMarker" {
			return "", nil
		}
		return encodeOpaqueToken(cfg, "upload", text)
	case textTransformEchoUploadToken:
		virtual := plan.query.Get("upload-id-marker")
		if virtual == "" {
			virtual = plan.query.Get("uploadId")
		}
		if virtual == "" {
			if text == "" && path == "ListMultipartUploadsResult/UploadIdMarker" {
				return "", nil
			}
			return "", fmt.Errorf("upstream echoed an upload token that was not requested")
		}
		origin, err := decodeOpaqueToken(cfg, "upload", virtual)
		if err != nil || text != origin {
			return "", fmt.Errorf("upstream upload token echo does not match request")
		}
		return virtual, nil
	case textTransformVirtualKeyEcho:
		if err := validateVirtualKeyEcho(path, text, plan, pathPrefix); err != nil {
			return "", err
		}
		return virtualizeResponseKey(path, text, plan, pathPrefix)
	case textTransformPlainQueryEcho:
		if err := validatePlainQueryEcho(path, text, plan); err != nil {
			return "", err
		}
		return text, nil
	case textTransformNumericQueryEcho:
		if err := validateNumericQueryEcho(path, text, plan); err != nil {
			return "", err
		}
		return text, nil
	case textTransformNonNegativeInteger:
		value, err := strconv.Atoi(strings.TrimSpace(text))
		if err != nil || value < 0 {
			return "", fmt.Errorf("upstream numeric field %s is invalid", path)
		}
		return text, nil
	case textTransformBoolean:
		value := strings.TrimSpace(text)
		if value != "true" && value != "false" {
			return "", fmt.Errorf("upstream boolean field %s is invalid", path)
		}
		return value, nil
	case textTransformRequiredNonempty:
		if strings.TrimSpace(text) == "" {
			return "", fmt.Errorf("upstream field %s is required", path)
		}
		return text, nil
	default:
		return text, nil
	}
}

func validateVirtualKeyEcho(path, text string, plan *S3OperationPlan, pathPrefix string) error {
	queryKey := ""
	switch path {
	case "ListBucketResult/Prefix", "ListMultipartUploadsResult/Prefix":
		queryKey = "prefix"
	case "ListBucketResult/Marker":
		queryKey = "marker"
	case "ListBucketResult/StartAfter":
		queryKey = "start-after"
	case "ListMultipartUploadsResult/KeyMarker":
		queryKey = "key-marker"
	default:
		return fmt.Errorf("no query echo contract for %s", path)
	}
	decoded := text
	if plan.query.Get("encoding-type") == "url" {
		var err error
		decoded, err = url.PathUnescape(text)
		if err != nil {
			return fmt.Errorf("decode upstream query echo %s: %w", path, err)
		}
	}
	expected := plan.query.Get(queryKey)
	if queryKey == "prefix" || expected != "" {
		expected = pathPrefix + expected
	}
	if decoded != expected {
		return fmt.Errorf("upstream %s echo does not match request", queryKey)
	}
	return nil
}

func validatePlainQueryEcho(path, text string, plan *S3OperationPlan) error {
	queryKey := ""
	switch path {
	case "ListBucketResult/Delimiter", "ListMultipartUploadsResult/Delimiter":
		queryKey = "delimiter"
	case "ListBucketResult/EncodingType", "ListMultipartUploadsResult/EncodingType":
		queryKey = "encoding-type"
	default:
		return fmt.Errorf("no plain query echo contract for %s", path)
	}
	decoded := text
	if queryKey == "delimiter" && plan.query.Get("encoding-type") == "url" {
		var err error
		decoded, err = url.PathUnescape(text)
		if err != nil {
			return fmt.Errorf("decode upstream delimiter echo: %w", err)
		}
	}
	if decoded != plan.query.Get(queryKey) {
		return fmt.Errorf("upstream %s echo does not match request", queryKey)
	}
	return nil
}

func validateNumericQueryEcho(path, text string, plan *S3OperationPlan) error {
	queryKey := ""
	defaultValue := 1000
	switch path {
	case "ListBucketResult/MaxKeys":
		queryKey = "max-keys"
	case "ListMultipartUploadsResult/MaxUploads":
		queryKey = "max-uploads"
	case "ListPartsResult/PartNumberMarker":
		queryKey, defaultValue = "part-number-marker", 0
	case "ListPartsResult/MaxParts":
		queryKey = "max-parts"
	default:
		return fmt.Errorf("no numeric query echo contract for %s", path)
	}
	actual, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || actual < 0 {
		return fmt.Errorf("upstream %s echo is invalid", queryKey)
	}
	requested, present := plan.query[queryKey]
	if present {
		expected, err := strconv.Atoi(requested[0])
		if err != nil || actual != expected {
			return fmt.Errorf("upstream %s echo does not match request", queryKey)
		}
	} else if defaultValue >= 0 && actual != defaultValue {
		return fmt.Errorf("upstream %s default does not match protocol", queryKey)
	}
	return nil
}

func virtualizeResponseKey(path, text string, plan *S3OperationPlan, pathPrefix string) (string, error) {
	urlEncoded := plan.query.Get("encoding-type") == "url"
	decoded := text
	if urlEncoded {
		var err error
		decoded, err = url.PathUnescape(text)
		if err != nil {
			return "", fmt.Errorf("decode upstream key field %s: %w", path, err)
		}
	}

	switch plan.responseProfile {
	case responseListObjects, responseListMultipartUploads:
		if decoded == "" {
			return "", nil
		}
		if !strings.HasPrefix(decoded, pathPrefix) {
			return "", fmt.Errorf("upstream key field %s is outside the configured prefix", path)
		}
	case responseCreateMultipart, responseListParts, responseCompleteMultipart:
		if decoded != pathPrefix+plan.objectKey {
			return "", fmt.Errorf("upstream key field %s does not match requested key", path)
		}
	}
	virtualKey := strings.TrimPrefix(decoded, pathPrefix)
	actualObjectKey := path == "ListBucketResult/Contents/Key" || path == "ListMultipartUploadsResult/Upload/Key"
	addressableKeyValue := actualObjectKey || path == "ListBucketResult/NextMarker" || path == "ListBucketResult/CommonPrefixes/Prefix" ||
		path == "ListMultipartUploadsResult/NextKeyMarker" || path == "ListMultipartUploadsResult/CommonPrefixes/Prefix"
	if addressableKeyValue {
		if actualObjectKey && virtualKey == "" {
			return "", fmt.Errorf("upstream result key %s becomes an empty virtual key", path)
		}
		if virtualKey != "" {
			if err := validateVirtualObjectKey(virtualKey); err != nil {
				return "", fmt.Errorf("upstream result key %s is not a valid virtual key: %w", path, err)
			}
		}
	}
	return stripListPathPrefix(text, pathPrefix, urlEncoded), nil
}

func knownResponsePath(profile S3ResponseProfile, path string) bool {
	root := expectedResponseRoot(profile)
	if path == root {
		return true
	}
	if knownResponsePaths[profile][path] {
		return true
	}
	_, ok := responseFieldRuleForPath(profile, path)
	return ok
}

func responsePathSet(root string, paths ...string) map[string]bool {
	result := make(map[string]bool, len(paths))
	for _, path := range paths {
		result[root+"/"+path] = true
	}
	return result
}

func filterSafeXMLAttributes(attributes []xml.Attr, cfg *VBucketConfig) []xml.Attr {
	filtered := attributes[:0]
	for _, attribute := range attributes {
		if containsSensitiveBackendValue(attribute.Value, cfg) {
			continue
		}
		if attribute.Name.Local == "xmlns" && attribute.Value == s3XMLNamespace {
			filtered = append(filtered, attribute)
		}
	}
	return filtered
}

func containsSensitiveBackendValue(value string, cfg *VBucketConfig) bool {
	endpoint := parseEndpoint(cfg.RealEndpoint)
	lowerValue := strings.ToLower(value)
	for _, sensitive := range []string{cfg.RealEndpoint, endpoint.Host, endpoint.Hostname()} {
		if sensitive != "" && strings.Contains(lowerValue, strings.ToLower(sensitive)) {
			return true
		}
	}
	for _, sensitive := range []string{
		cfg.RealBucket, cfg.RealAccessKey,
		cfg.RealSecretKey, cfg.RealRegion, cfg.PathPrefix, normalizedPathPrefix(cfg.PathPrefix),
	} {
		if sensitive != "" && strings.Contains(value, sensitive) {
			return true
		}
	}
	return false
}

func normalizedPathPrefix(prefix string) string {
	if prefix == "" {
		return ""
	}
	return strings.TrimSuffix(prefix, "/") + "/"
}

func virtualResponseLocation(plan *S3OperationPlan) string {
	// A relative, path-style URL is valid for this informational S3 field and
	// avoids guessing the public scheme/host from untrusted request metadata.
	path := "/" + awsURIEncode(plan.objectKey)
	if !plan.isVHost {
		path = "/" + plan.bucket + path
	}
	return path
}

func copySafeResponseHeaders(src, dst http.Header, cfg *VBucketConfig, plan *S3OperationPlan, status int) error {
	hopByHop := hopByHopHeaderSet(src)
	staged := make(http.Header)
	for name, values := range src {
		canonical := http.CanonicalHeaderKey(name)
		if hopByHop[canonical] || !safeS3ResponseHeader(canonical) {
			continue
		}
		for _, value := range values {
			if canonical == "X-Amz-Version-Id" || canonical == "X-Amz-Copy-Source-Version-Id" {
				var err error
				value, err = encodeOpaqueToken(cfg, "version", value)
				if err != nil {
					return err
				}
			}
			allowUserCollision := status >= 200 && status < 300 && operationReadsObject(plan.kind) && userControlledResponseHeader(canonical)
			if !allowUserCollision && containsSensitiveBackendValue(value, cfg) {
				continue
			}
			staged.Add(canonical, value)
		}
	}
	for name, values := range staged {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
	return nil
}

func operationReadsObject(kind S3OperationKind) bool {
	switch kind {
	case operationGetObject, operationGetObjectVersion, operationHeadObject, operationHeadObjectVersion:
		return true
	default:
		return false
	}
}

func userControlledResponseHeader(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "x-amz-meta-") || strings.HasPrefix(lower, "x-amz-checksum-") {
		return true
	}
	switch name {
	case "Cache-Control", "Content-Disposition", "Content-Encoding", "Content-Language",
		"Content-Type", "Etag", "Expires", "Last-Modified":
		return true
	default:
		return false
	}
}

func dropDiscardedBodyHeaders(headers http.Header) {
	for name := range headers {
		lower := strings.ToLower(name)
		if lower == "content-length" || lower == "content-md5" || lower == "content-encoding" || lower == "content-range" || lower == "digest" {
			headers.Del(name)
		}
	}
}

func dropTransformedRepresentationHeaders(headers http.Header, profile S3ResponseProfile) {
	dropDiscardedBodyHeaders(headers)
	if profile != responseListObjects && profile != responseListMultipartUploads && profile != responseListParts {
		return
	}
	for name := range headers {
		lower := strings.ToLower(name)
		if lower == "etag" || strings.HasPrefix(lower, "x-amz-checksum-") {
			headers.Del(name)
		}
	}
}

func safeS3ResponseHeader(name string) bool {
	if strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") || strings.HasPrefix(strings.ToLower(name), "x-amz-checksum-") {
		return true
	}
	switch name {
	case "Accept-Ranges", "Cache-Control", "Content-Disposition", "Content-Encoding",
		"Content-Language", "Content-Length", "Content-Range", "Content-Type", "Etag",
		"Expires", "Last-Modified", "Retry-After", "X-Amz-Delete-Marker",
		"X-Amz-Expiration", "X-Amz-Missing-Meta", "X-Amz-Object-Lock-Legal-Hold",
		"X-Amz-Object-Lock-Mode", "X-Amz-Object-Lock-Retain-Until-Date",
		"X-Amz-Replication-Status", "X-Amz-Restore", "X-Amz-Server-Side-Encryption",
		"X-Amz-Server-Side-Encryption-Customer-Algorithm", "X-Amz-Server-Side-Encryption-Customer-Key-Md5",
		"X-Amz-Storage-Class", "X-Amz-Tagging-Count", "X-Amz-Version-Id", "X-Amz-Copy-Source-Version-Id":
		return true
	default:
		return false
	}
}
