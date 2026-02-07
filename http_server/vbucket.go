package http_server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Resolver provides the three lookups the proxy needs. Implemented by
// controlplane.Client; tests can supply a lightweight stub.
type Resolver interface {
	LookupCredentials(ctx context.Context, accessKeyID string) (*VirtualCredentials, error)
	LookupBaseHost(ctx context.Context, hostname string) (string, bool, error)
	LookupVBucket(ctx context.Context, accessKeyID, bucketName string) (*VBucketConfig, error)
}

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
