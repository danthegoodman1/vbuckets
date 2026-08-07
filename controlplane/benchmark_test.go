package controlplane

import (
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func BenchmarkLocalCacheBoundedRandomCardinality(b *testing.B) {
	now := time.Now()
	cache := newLocalCache[string, cachedCredentials](10_000, nil, func() time.Time { return now })
	entry := cachedCredentials{Found: false, Revision: 1, TTL: time.Minute}
	keys := make([]string, 65_536)
	for index := range keys {
		keys[index] = fmt.Sprintf("random-key-%d", index)
	}
	b.ReportAllocs()
	b.ResetTimer()
	state := uint64(0x9e3779b97f4a7c15)
	for range b.N {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		cache.Set(keys[state&65_535], entry, time.Minute)
	}
	b.StopTimer()
	if cache.Len() > 10_000 {
		b.Fatalf("cache exceeded capacity: %d", cache.Len())
	}
}

func BenchmarkBaseDomainLongestSuffix(b *testing.B) {
	c := NewClient("benchmark", zerolog.Nop())
	c.state, c.revision, c.cursor, c.barrierRequired = StateReady, 1, "cursor-1", false
	for index := range 10_000 {
		c.baseHosts[fmt.Sprintf("s3-%d.example.com", index)] = 1
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		base, found, err := c.LookupBaseHost(b.Context(), "tenant.bucket.s3-9999.example.com")
		if err != nil || !found || base != "s3-9999.example.com" {
			b.Fatalf("unexpected lookup result: base=%q found=%t err=%v", base, found, err)
		}
	}
}
