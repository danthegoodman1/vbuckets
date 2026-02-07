package http_server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/danthegoodman1/vbuckets/env"
)

// VirtualCredentials holds the secret key and IAM policy for a virtual access key ID.
// Looked up before signature verification so auth is checked first.
// The IAM policy travels with the identity -- the key defines what you can do,
// the vbucket defines where things go.
type VirtualCredentials struct {
	SecretKey string
	IAMPolicy IAMPolicy
}

// VBucketConfig holds the mapping from a virtual bucket to a real S3 backend.
// Looked up after signature verification.
type VBucketConfig struct {
	RealEndpoint     string // full URL, e.g. "https://s3.us-east-1.amazonaws.com" or "http://localhost:3900"
	RealBucket       string
	RealAccessKey    string
	RealSecretKey    string
	RealRegion       string
	PathPrefix       string // optional prefix prepended to object keys
	RealUsePathStyle bool   // when true, use path-style addressing to the real backend
}

// TODO: replace with control plane lookup (database, API call, etc.)
// Currently returns static credentials from environment variables.
func lookupCredentials(accessKeyID string) (*VirtualCredentials, error) {
	if env.VirtualAccessKeyID == "" {
		return nil, fmt.Errorf("VIRTUAL_ACCESS_KEY_ID not configured")
	}

	if accessKeyID != env.VirtualAccessKeyID {
		return nil, fmt.Errorf("unknown access key ID: %s", accessKeyID)
	}

	return &VirtualCredentials{
		SecretKey: env.VirtualSecretAccessKey,
	}, nil
}

// TODO: replace with control plane lookup (database, API call, etc.)
// Currently returns static config from environment variables.
func lookupVBucket(accessKeyID, bucketName string) (*VBucketConfig, error) {
	if env.VirtualBucketName != "" && bucketName != env.VirtualBucketName {
		return nil, fmt.Errorf("unknown bucket: %s", bucketName)
	}

	return &VBucketConfig{
		RealEndpoint:     env.RealS3Endpoint,
		RealBucket:       env.RealBucket,
		RealAccessKey:    env.RealAccessKeyID,
		RealSecretKey:    env.RealSecretAccessKey,
		RealRegion:       env.RealRegion,
		PathPrefix:       env.RealPathPrefix,
		RealUsePathStyle: env.RealUsePathStyle,
	}, nil
}

// lookupBaseHost takes the full hostname from the request and returns the
// matching base domain, if any. This determines whether the request is
// using vhost-style addressing (hostname has a subdomain prefix before the
// base domain) or path-style (hostname IS the base domain).
//
// TODO: replace with control plane lookup that walks the domain parts
// right-to-left until it finds a registered base domain in its DB.
// Currently returns the static S3_BASE_HOST env var if it matches.
func lookupBaseHost(hostname string) (baseHost string, found bool) {
	if env.S3BaseHost == "" {
		return "", false
	}

	// Exact match means path-style (host is the base domain itself)
	if hostname == env.S3BaseHost {
		return env.S3BaseHost, true
	}

	// Subdomain match means vhost-style
	if strings.HasSuffix(hostname, "."+env.S3BaseHost) {
		return env.S3BaseHost, true
	}

	return "", false
}

// resolveBucket determines the bucket name and object key from the request,
// detecting whether the client is using virtual-hosted style or path style.
//
// Virtual-hosted style: bucket.BASE_HOST/key
// Path style:           BASE_HOST/bucket/key (or unknown host)
func resolveBucket(r *http.Request) (bucket, objectKey string, isVHost bool) {
	host := r.Host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	if baseHost, found := lookupBaseHost(host); found && host != baseHost {
		// vhost-style: host is a subdomain of the base domain
		bucket = strings.TrimSuffix(host, "."+baseHost)
		objectKey = strings.TrimPrefix(r.URL.Path, "/")
		return bucket, objectKey, true
	}

	// Path style: first path segment is the bucket
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	bucket = parts[0]
	if len(parts) > 1 {
		objectKey = parts[1]
	}
	return bucket, objectKey, false
}
