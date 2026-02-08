package http_server

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/danthegoodman1/vbuckets/env"
)

const unsignedPayload = "UNSIGNED-PAYLOAD"

var errRequestTimeTooSkewed = errors.New("request time too skewed")

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

	for _, part := range parts {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("malformed authorization part: %s", part)
		}
		switch k {
		case "Credential":
			credParts := strings.SplitN(v, "/", 5)
			if len(credParts) != 5 || credParts[4] != "aws4_request" {
				return nil, fmt.Errorf("malformed credential: %s", v)
			}
			info.AccessKeyID = credParts[0]
			info.Date = credParts[1]
			info.Region = credParts[2]
			info.Service = credParts[3]
			info.Scope = strings.Join(credParts[1:], "/")
		case "SignedHeaders":
			info.SignedHeaders = strings.Split(v, ";")
			sort.Strings(info.SignedHeaders)
		case "Signature":
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

// buildCanonicalRequest constructs the canonical request string per the AWS SigV4 spec.
// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html#create-canonical-request
//
// The payload hash is taken from the x-amz-content-sha256 header, which must
// be present. The body is never read -- the header value (whether a real hash
// or "UNSIGNED-PAYLOAD") is itself covered by the signature.
func buildCanonicalRequest(r *http.Request, signedHeaders []string) string {
	var b strings.Builder

	b.WriteString(r.Method)
	b.WriteByte('\n')

	// S3 uses raw path (no double-encoding of path segments)
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	b.WriteString(path)
	b.WriteByte('\n')

	b.WriteString(canonicalQueryString(r.URL.Query()))
	b.WriteByte('\n')

	// Canonical headers must be sorted and lowercased
	sorted := make([]string, len(signedHeaders))
	copy(sorted, signedHeaders)
	sort.Strings(sorted)

	for _, h := range sorted {
		var val string
		if h == "host" {
			val = r.Host
		} else {
			val = r.Header.Get(h)
		}
		b.WriteString(strings.ToLower(h))
		b.WriteByte(':')
		b.WriteString(strings.TrimSpace(val))
		b.WriteByte('\n')
	}
	b.WriteByte('\n') // blank line after headers

	b.WriteString(strings.Join(sorted, ";"))
	b.WriteByte('\n')

	b.WriteString(r.Header.Get("x-amz-content-sha256"))

	return b.String()
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
// read -- the x-amz-content-sha256 header value is used as the payload hash.
func verifySignature(r *http.Request, authInfo *AuthInfo, secretKey string) error {
	return verifySignatureAtTime(r, authInfo, secretKey, time.Now().UTC(), env.SigV4MaxClockSkew)
}

func verifySignatureAtTime(r *http.Request, authInfo *AuthInfo, secretKey string, now time.Time, maxSkew time.Duration) error {
	if r.Header.Get("x-amz-content-sha256") == "" {
		return fmt.Errorf("missing x-amz-content-sha256 header")
	}

	datetime := r.Header.Get("X-Amz-Date")
	if datetime == "" {
		return fmt.Errorf("missing X-Amz-Date header")
	}
	requestTime, err := time.Parse("20060102T150405Z", datetime)
	if err != nil {
		return fmt.Errorf("invalid X-Amz-Date header: %w", err)
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

	stringToSign := buildStringToSign(datetime, authInfo.Scope, canonicalRequest)
	signingKey := computeSigningKey(secretKey, authInfo.Date, authInfo.Region, authInfo.Service)
	expectedSig := fmt.Sprintf("%x", hmacSHA256(signingKey, []byte(stringToSign)))

	if !hmac.Equal([]byte(expectedSig), []byte(authInfo.Signature)) {
		return fmt.Errorf("signature mismatch")
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
