package http_server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/danthegoodman1/vbuckets/env"
)

// VirtualCredentials holds the secret key for a virtual access key ID.
// Looked up before signature verification so auth is checked first.
type VirtualCredentials struct {
	SecretKey string
}

// VBucketConfig holds the mapping from a virtual bucket to a real S3 backend.
// Looked up after signature verification.
type VBucketConfig struct {
	RealEndpoint     string // e.g. "s3.us-east-1.amazonaws.com"
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

// resolveBucket determines the bucket name and object key from the request,
// detecting whether the client is using virtual-hosted style or path style.
//
// Virtual-hosted style: bucket.BASE_HOST/key
// Path style:           BASE_HOST/bucket/key
func resolveBucket(r *http.Request, baseHost string) (bucket, objectKey string, isVHost bool) {
	host := r.Host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Check for virtual-hosted style: host is a subdomain of baseHost
	if baseHost != "" && strings.HasSuffix(host, "."+baseHost) {
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
