package controlplane

import (
	"time"

	"github.com/maypok86/otter/v2"

	"github.com/danthegoodman1/vbuckets/env"
	"github.com/danthegoodman1/vbuckets/http_server"
)

type cachedCredentials struct {
	*http_server.VirtualCredentials
	TTL time.Duration
}

type cachedBaseHost struct {
	BaseHost string
	Found    bool
	TTL      time.Duration
}

type cachedVBucket struct {
	*http_server.VBucketConfig
	TTL time.Duration
}

type caches struct {
	credentials *otter.Cache[string, cachedCredentials]
	baseHosts   *otter.Cache[string, cachedBaseHost]
	vbuckets    *otter.Cache[string, cachedVBucket]
}

func newCaches() *caches {
	return &caches{
		credentials: otter.Must(&otter.Options[string, cachedCredentials]{
			MaximumSize: env.CacheMaxCredentials,
			ExpiryCalculator: otter.ExpiryWritingFunc(func(e otter.Entry[string, cachedCredentials]) time.Duration {
				return e.Value.TTL
			}),
		}),
		baseHosts: otter.Must(&otter.Options[string, cachedBaseHost]{
			MaximumSize: env.CacheMaxBaseHosts,
			ExpiryCalculator: otter.ExpiryWritingFunc(func(e otter.Entry[string, cachedBaseHost]) time.Duration {
				return e.Value.TTL
			}),
		}),
		vbuckets: otter.Must(&otter.Options[string, cachedVBucket]{
			MaximumSize: env.CacheMaxVBuckets,
			ExpiryCalculator: otter.ExpiryWritingFunc(func(e otter.Entry[string, cachedVBucket]) time.Duration {
				return e.Value.TTL
			}),
		}),
	}
}

func vbucketCacheKey(accessKeyID, bucketName string) string {
	return accessKeyID + "/" + bucketName
}
