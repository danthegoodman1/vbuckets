package http_server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/danthegoodman1/vbuckets/iam"
)

var (
	ErrVBucketAlreadyOwnedByYou = errors.New("vbucket already owned by you")
	ErrVBucketAlreadyExists     = errors.New("vbucket already exists")
	ErrInvalidVBucketName       = errors.New("invalid vbucket name")
	ErrInvalidVBucketArgument   = errors.New("invalid vbucket argument")
	ErrVBucketAccessDenied      = errors.New("vbucket access denied")
)

// Resolver provides the three lookups the proxy needs. Implemented by
// controlplane.Client; tests can supply a lightweight stub.
type Resolver interface {
	LookupCredentials(ctx context.Context, accessKeyID string) (*VirtualCredentials, error)
	LookupBaseHost(ctx context.Context, hostname string) (string, bool, error)
	LookupVBucket(ctx context.Context, accessKeyID, bucketName string) (*VBucketConfig, error)
	CreateVBucket(ctx context.Context, accessKeyID, bucketName, locationConstraint string) (*VBucketConfig, error)
	ListVBuckets(ctx context.Context, accessKeyID string) ([]ListedVBucket, error)
}

// VirtualCredentials holds the secret key and IAM policy for a virtual access key ID.
// Looked up before signature verification so auth is checked first.
// The IAM policy travels with the identity -- the key defines what you can do,
// the vbucket defines where things go.
type VirtualCredentials struct {
	SecretKey string
	IAMPolicy *iam.Policy
}

// VBucketConfig holds the mapping from a virtual bucket to a real S3 backend.
// Looked up after signature verification.
type VBucketConfig struct {
	RealEndpoint      string // full URL, e.g. "https://s3.us-east-1.amazonaws.com" or "http://localhost:3900"
	RealBucket        string
	RealAccessKey     string
	RealSecretKey     string
	RealRegion        string
	PathPrefix        string             // optional prefix prepended to object keys
	RealUsePathStyle  bool               // when true, use path-style addressing to the real backend
	RoutingTokenKey   []byte             // stable mapping-scoped 32-byte key for opaque routing tokens
	routingTokenCodec *opaqueTokenCipher // immutable codec reused within normalized mapping snapshots
}

func (c *VBucketConfig) Clone() *VBucketConfig {
	if c == nil {
		return nil
	}
	clone := *c
	clone.RoutingTokenKey = append([]byte(nil), c.RoutingTokenKey...)
	return &clone
}

// NormalizeVBucketConfig validates a control-plane mapping and returns an
// immutable-by-convention copy in the canonical form used by the proxy. It is
// intentionally safe to call at either cache insertion or a Resolver boundary.
func NormalizeVBucketConfig(cfg *VBucketConfig) (*VBucketConfig, error) {
	if cfg == nil {
		return nil, fmt.Errorf("vbucket mapping is required")
	}
	normalized := *cfg.Clone()
	if len(normalized.RoutingTokenKey) != 32 {
		return nil, fmt.Errorf("routing token key must be exactly 32 bytes")
	}
	endpoint := strings.TrimSpace(normalized.RealEndpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("real endpoint is required")
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse real endpoint: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("real endpoint must be an absolute HTTP(S) URL")
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("real endpoint must not contain credentials, path, query, or fragment")
	}
	if _, err := url.ParseRequestURI("//" + u.Host); err != nil {
		return nil, fmt.Errorf("real endpoint host is invalid: %w", err)
	}
	if !normalized.RealUsePathStyle && net.ParseIP(u.Hostname()) != nil {
		return nil, fmt.Errorf("virtual-hosted addressing requires a DNS endpoint; IP endpoints must use path style")
	}
	if port := u.Port(); port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return nil, fmt.Errorf("real endpoint port must be from 1 through 65535")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("real endpoint port is empty")
	}
	u.Path, u.RawPath = "", ""
	normalized.RealEndpoint = strings.TrimSuffix(u.String(), "/")

	normalized.RealBucket = strings.TrimSpace(normalized.RealBucket)
	if !isValidBucketName(normalized.RealBucket) {
		return nil, fmt.Errorf("real bucket is invalid")
	}
	if !accessKeyIDPattern.MatchString(normalized.RealAccessKey) || !printableASCII(normalized.RealSecretKey) {
		return nil, fmt.Errorf("real credentials are required")
	}
	normalized.RealRegion = strings.TrimSpace(normalized.RealRegion)
	if !backendRegionPattern.MatchString(normalized.RealRegion) {
		return nil, fmt.Errorf("real region is required")
	}

	prefix := strings.Trim(normalized.PathPrefix, "/")
	if prefix != "" {
		for _, segment := range strings.Split(prefix, "/") {
			if segment == "" || segment == "." || segment == ".." || strings.ContainsRune(segment, '\\') || !noASCIIControls(segment) {
				return nil, fmt.Errorf("path prefix contains an unsafe segment")
			}
		}
	}
	normalized.PathPrefix = prefix
	if normalized.routingTokenCodec == nil || !normalized.routingTokenCodec.matches(&normalized) {
		codec, err := newOpaqueTokenCipher(&normalized)
		if err != nil {
			return nil, fmt.Errorf("initialize routing token codec: %w", err)
		}
		normalized.routingTokenCodec = codec
	}
	return &normalized, nil
}

var (
	backendRegionPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

func printableASCII(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func noASCIIControls(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

type ListedVBucket struct {
	Name         string
	CreationDate time.Time
}

// resolveBucket determines the bucket name and object key from the request,
// detecting whether the client is using virtual-hosted style or path style.
//
// Virtual-hosted style: bucket.BASE_HOST/key
// Path style:           BASE_HOST/bucket/key (or unknown host)
func resolveBucket(resolver Resolver, r *http.Request) (bucket, objectKey string, isVHost bool, err error) {
	host := r.Host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	baseHost, found, err := resolver.LookupBaseHost(r.Context(), host)
	if err != nil {
		return "", "", false, fmt.Errorf("base host lookup: %w", err)
	}

	if found && host != baseHost {
		bucket = strings.TrimSuffix(host, "."+baseHost)
		objectKey = strings.TrimPrefix(r.URL.Path, "/")
		return bucket, objectKey, true, nil
	}

	// Path style: first path segment is the bucket
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	bucket = parts[0]
	if len(parts) > 1 {
		objectKey = parts[1]
	}
	return bucket, objectKey, false, nil
}
