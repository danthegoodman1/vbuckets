package http_server

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/danthegoodman1/vbuckets/env"
)

const unsignedPayload = "UNSIGNED-PAYLOAD"

var accessKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

var (
	errRequestTimeTooSkewed   = errors.New("request time too skewed")
	errUnsupportedPayloadHash = errors.New("unsupported payload hash")
	errUnsignedAmzHeader      = errors.New("unsigned x-amz header")
	errUnsupportedAuthMode    = errors.New("unsupported authentication mode")
)

type AuthInfo struct {
	AccessKeyID   string
	Date          string // YYYYMMDD
	Region        string
	Service       string
	SignedHeaders []string
	Signature     string
	// Raw credential scope string: "date/region/service/aws4_request"
	Scope string
}

// parseAuthorizationHeader parses an AWS SigV4 Authorization header into its components.
// Expected format: AWS4-HMAC-SHA256 Credential=AKID/date/region/service/aws4_request, SignedHeaders=h1;h2;h3, Signature=hex
func parseAuthorizationHeader(header string) (*AuthInfo, error) {
	if !strings.HasPrefix(header, "AWS4-HMAC-SHA256 ") {
		return nil, fmt.Errorf("unsupported authorization algorithm")
	}
	header = strings.TrimPrefix(header, "AWS4-HMAC-SHA256 ")

	parts := strings.Split(header, ", ")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed authorization header: expected 3 parts, got %d", len(parts))
	}

	info := &AuthInfo{}

	expectedParts := [...]string{"Credential", "SignedHeaders", "Signature"}
	for i, part := range parts {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("malformed authorization part: %s", part)
		}
		if k != expectedParts[i] {
			return nil, fmt.Errorf("authorization fields must be %s in canonical order", strings.Join(expectedParts[:], ", "))
		}
		switch k {
		case "Credential":
			credParts := strings.SplitN(v, "/", 5)
			if len(credParts) != 5 || credParts[0] == "" || credParts[1] == "" || credParts[2] == "" || credParts[3] != "s3" || credParts[4] != "aws4_request" {
				return nil, fmt.Errorf("malformed credential: %s", v)
			}
			if _, err := time.Parse("20060102", credParts[1]); err != nil {
				return nil, fmt.Errorf("malformed credential date: %s", credParts[1])
			}
			if !accessKeyIDPattern.MatchString(credParts[0]) {
				return nil, fmt.Errorf("access key ID must contain 1 to 128 letters, digits, dots, underscores, or hyphens")
			}
			info.AccessKeyID = credParts[0]
			info.Date = credParts[1]
			info.Region = credParts[2]
			info.Service = credParts[3]
			info.Scope = strings.Join(credParts[1:], "/")
		case "SignedHeaders":
			info.SignedHeaders = strings.Split(v, ";")
			if err := validateSignedHeaders(info.SignedHeaders); err != nil {
				return nil, err
			}
		case "Signature":
			if len(v) != sha256.Size*2 || strings.Trim(v, "0123456789abcdef") != "" {
				return nil, fmt.Errorf("signature must be 64 lowercase hexadecimal characters")
			}
			info.Signature = v
		default:
			return nil, fmt.Errorf("unknown authorization part: %s", k)
		}
	}

	if info.AccessKeyID == "" || info.Signature == "" || len(info.SignedHeaders) == 0 {
		return nil, fmt.Errorf("incomplete authorization header")
	}

	return info, nil
}

func validateSignedHeaders(headers []string) error {
	if len(headers) == 0 {
		return fmt.Errorf("SignedHeaders must not be empty")
	}
	hasHost := false
	hasDate := false
	for i, header := range headers {
		if header == "" || header != strings.ToLower(header) {
			return fmt.Errorf("SignedHeaders must contain lowercase header names")
		}
		if i > 0 && headers[i-1] >= header {
			return fmt.Errorf("SignedHeaders must be sorted and unique")
		}
		hasHost = hasHost || header == "host"
		hasDate = hasDate || header == "x-amz-date"
	}
	if !hasHost {
		return fmt.Errorf("SignedHeaders must include host")
	}
	if !hasDate {
		return fmt.Errorf("SignedHeaders must include x-amz-date")
	}
	return nil
}

// buildCanonicalRequest constructs the canonical request string per the AWS SigV4 spec.
// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html#create-canonical-request
//
// The payload hash is taken from the x-amz-content-sha256 header, which must
// be present and must be UNSIGNED-PAYLOAD. The body is never read.
func buildCanonicalRequest(r *http.Request, signedHeaders []string) string {
	var b strings.Builder

	b.WriteString(r.Method)
	b.WriteByte('\n')

	// S3 uses the wire-escaped path without generic SigV4 double escaping.
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	b.WriteString(path)
	b.WriteByte('\n')

	b.WriteString(canonicalQueryString(r.URL.Query()))
	b.WriteByte('\n')

	for _, h := range signedHeaders {
		var values []string
		if h == "host" {
			host := r.Host
			if host == "" {
				host = r.URL.Host
			}
			values = []string{host}
		} else if h == "content-length" && len(r.Header.Values(h)) == 0 && r.ContentLength > 0 {
			values = []string{fmt.Sprintf("%d", r.ContentLength)}
		} else {
			values = r.Header.Values(h)
		}
		b.WriteString(h)
		b.WriteByte(':')
		for i, value := range values {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(canonicalHeaderValue(value))
		}
		b.WriteByte('\n')
	}
	b.WriteByte('\n') // blank line after headers

	b.WriteString(strings.Join(signedHeaders, ";"))
	b.WriteByte('\n')

	b.WriteString(r.Header.Get("x-amz-content-sha256"))

	return b.String()
}

func canonicalHeaderValue(value string) string {
	value = strings.TrimSpace(value)
	for strings.Contains(value, "  ") {
		value = strings.ReplaceAll(value, "  ", " ")
	}
	return value
}

func canonicalQueryString(query url.Values) string {
	// Must be sorted by key name, then by value
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pairs []string
	for _, k := range keys {
		vals := query[k]
		sort.Strings(vals)
		for _, v := range vals {
			pairs = append(pairs, awsURIEncode(k)+"="+awsURIEncode(v))
		}
	}
	return strings.Join(pairs, "&")
}

// awsURIEncode performs RFC 3986 URI encoding as required by AWS SigV4.
// Only unreserved characters (A-Z, a-z, 0-9, '-', '_', '.', '~') are left unencoded.
// Notably, spaces become %20 (not +), and ~ is NOT encoded.
func awsURIEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func buildStringToSign(datetime, scope, canonicalRequest string) string {
	hash := sha256.Sum256([]byte(canonicalRequest))
	return "AWS4-HMAC-SHA256\n" +
		datetime + "\n" +
		scope + "\n" +
		fmt.Sprintf("%x", hash)
}

func computeSigningKey(secret, date, region, service string) []byte {
	dateKey := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	dateRegionKey := hmacSHA256(dateKey, []byte(region))
	dateRegionServiceKey := hmacSHA256(dateRegionKey, []byte(service))
	return hmacSHA256(dateRegionServiceKey, []byte("aws4_request"))
}

// verifySignature checks that the request's SigV4 signature matches the expected
// signature derived from the provided secret key. The request body is never
// read; clients must use UNSIGNED-PAYLOAD so streaming remains possible.
func verifySignature(r *http.Request, authInfo *AuthInfo, secretKey string) error {
	return verifySignatureAtTime(r, authInfo, secretKey, time.Now().UTC(), env.SigV4MaxClockSkew)
}

func verifySignatureAtTime(r *http.Request, authInfo *AuthInfo, secretKey string, now time.Time, maxSkew time.Duration) error {
	if authInfo == nil {
		return fmt.Errorf("missing authentication information")
	}
	if err := validateSignedHeaders(authInfo.SignedHeaders); err != nil {
		return err
	}
	if authInfo.Service != "s3" {
		return fmt.Errorf("credential scope service must be s3")
	}
	if len(r.Header.Values("x-amz-security-token")) != 0 {
		return fmt.Errorf("%w: session tokens are not supported", errUnsupportedAuthMode)
	}
	if len(r.Header.Values("x-amz-trailer")) != 0 || len(r.Trailer) != 0 {
		return fmt.Errorf("%w: signed trailers are not supported", errUnsupportedAuthMode)
	}
	if err := requireSingletonHeader(r, "x-amz-content-sha256"); err != nil {
		return err
	}
	if err := requireSingletonHeader(r, "x-amz-date"); err != nil {
		return err
	}
	payloadHash := r.Header.Get("x-amz-content-sha256")
	if payloadHash == "" {
		return fmt.Errorf("missing x-amz-content-sha256 header")
	}
	if payloadHash != unsignedPayload {
		return fmt.Errorf("%w: x-amz-content-sha256 must be %s", errUnsupportedPayloadHash, unsignedPayload)
	}
	if err := requireSignedAmzHeaders(r, authInfo.SignedHeaders); err != nil {
		return err
	}

	datetime := r.Header.Get("X-Amz-Date")
	if datetime == "" {
		return fmt.Errorf("missing X-Amz-Date header")
	}
	requestTime, err := time.Parse("20060102T150405Z", datetime)
	if err != nil {
		return fmt.Errorf("invalid X-Amz-Date header: %w", err)
	}
	if authInfo.Date != requestTime.UTC().Format("20060102") {
		return fmt.Errorf("credential scope date does not match X-Amz-Date")
	}
	expectedScope := authInfo.Date + "/" + authInfo.Region + "/s3/aws4_request"
	if authInfo.Scope != expectedScope {
		return fmt.Errorf("credential scope is inconsistent")
	}
	if maxSkew > 0 {
		skew := now.Sub(requestTime)
		if skew < 0 {
			skew = -skew
		}
		if skew > maxSkew {
			return fmt.Errorf("%w", errRequestTimeTooSkewed)
		}
	}

	canonicalRequest := buildCanonicalRequest(r, authInfo.SignedHeaders)
	signingKey := computeSigningKey(secretKey, authInfo.Date, authInfo.Region, authInfo.Service)
	expectedSig := signatureForCanonicalRequest(datetime, authInfo.Scope, canonicalRequest, signingKey)

	if !hmac.Equal([]byte(expectedSig), []byte(authInfo.Signature)) {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}

func signatureForCanonicalRequest(datetime, scope, canonicalRequest string, signingKey []byte) string {
	stringToSign := buildStringToSign(datetime, scope, canonicalRequest)
	return fmt.Sprintf("%x", hmacSHA256(signingKey, []byte(stringToSign)))
}

func requireSingletonHeader(r *http.Request, name string) error {
	if len(r.Header.Values(name)) != 1 {
		return fmt.Errorf("%s header must occur exactly once", name)
	}
	return nil
}

func requireSignedAmzHeaders(r *http.Request, signedHeaders []string) error {
	signed := make(map[string]bool, len(signedHeaders))
	for _, header := range signedHeaders {
		signed[strings.ToLower(header)] = true
	}

	for header := range r.Header {
		lower := strings.ToLower(header)
		if !strings.HasPrefix(lower, "x-amz-") {
			continue
		}
		// S3 treats x-amz-content-sha256 as the canonical payload hash even
		// when it is not listed in SignedHeaders.
		if lower == "x-amz-content-sha256" {
			continue
		}
		if !signed[lower] {
			return fmt.Errorf("%w: %s", errUnsignedAmzHeader, lower)
		}
	}

	return nil
}

// signRequest signs an outbound HTTP request using AWS SigV4.
// It sets the Authorization, X-Amz-Date, and x-amz-content-sha256 headers.
// The payload hash is always UNSIGNED-PAYLOAD since we're a trusted proxy
// forwarding over HTTPS and never buffer the body.
func signRequest(r *http.Request, accessKey, secretKey, region string) {
	now := time.Now().UTC()
	datetime := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	r.Header.Set("X-Amz-Date", datetime)
	r.Header.Set("x-amz-content-sha256", unsignedPayload)

	// Sign all headers that are present on the request
	signedHeaders := []string{"host"}
	for h := range r.Header {
		lower := strings.ToLower(h)
		if lower == "host" {
			continue
		}
		signedHeaders = append(signedHeaders, lower)
	}
	sort.Strings(signedHeaders)

	scope := date + "/" + region + "/s3/aws4_request"

	canonicalRequest := buildCanonicalRequest(r, signedHeaders)
	stringToSign := buildStringToSign(datetime, scope, canonicalRequest)
	signingKey := computeSigningKey(secretKey, date, region, "s3")
	signature := fmt.Sprintf("%x", hmacSHA256(signingKey, []byte(stringToSign)))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, scope, strings.Join(signedHeaders, ";"), signature)

	r.Header.Set("Authorization", authHeader)
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
