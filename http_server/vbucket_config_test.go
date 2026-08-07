package http_server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validTestVBucketConfig() *VBucketConfig {
	return &VBucketConfig{
		RealEndpoint:     "s3.example.com/",
		RealBucket:       "real-bucket",
		RealAccessKey:    "real-access",
		RealSecretKey:    "real-secret",
		RealRegion:       "us-east-1",
		PathPrefix:       "/tenant/a/",
		RealUsePathStyle: true,
		RoutingTokenKey:  testRoutingTokenKey,
	}
}

func TestNormalizeVBucketConfigCanonicalizesAndDefensivelyCopies(t *testing.T) {
	input := validTestVBucketConfig()
	normalized, err := NormalizeVBucketConfig(input)
	require.NoError(t, err)
	assert.Equal(t, "https://s3.example.com", normalized.RealEndpoint)
	assert.Equal(t, "tenant/a", normalized.PathPrefix)
	input.RoutingTokenKey[0] ^= 0xff
	assert.NotEqual(t, input.RoutingTokenKey[0], normalized.RoutingTokenKey[0])
}

func TestNormalizeVBucketConfigReusesMatchingRoutingCodec(t *testing.T) {
	first, err := NormalizeVBucketConfig(validTestVBucketConfig())
	require.NoError(t, err)
	require.NotNil(t, first.routingTokenCodec)
	second, err := NormalizeVBucketConfig(first)
	require.NoError(t, err)
	assert.Same(t, first.routingTokenCodec, second.routingTokenCodec, "defensive hot-path normalization must retain the immutable mapping codec")

	retargeted := first.Clone()
	retargeted.PathPrefix = "tenant/b"
	third, err := NormalizeVBucketConfig(retargeted)
	require.NoError(t, err)
	assert.NotSame(t, first.routingTokenCodec, third.routingTokenCodec, "namespace changes require a newly bound codec")
}

func BenchmarkNormalizeVBucketConfig(b *testing.B) {
	normalized, err := NormalizeVBucketConfig(validTestVBucketConfig())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := NormalizeVBucketConfig(normalized); err != nil {
			b.Fatal(err)
		}
	}
}

func TestNormalizeVBucketConfigRejectsUnsafeMappings(t *testing.T) {
	tests := map[string]func(*VBucketConfig){
		"nil key":                func(c *VBucketConfig) { c.RoutingTokenKey = nil },
		"short key":              func(c *VBucketConfig) { c.RoutingTokenKey = []byte("short") },
		"endpoint credentials":   func(c *VBucketConfig) { c.RealEndpoint = "https://user:pass@s3.example.com" },
		"endpoint path":          func(c *VBucketConfig) { c.RealEndpoint = "https://s3.example.com/path" },
		"endpoint query":         func(c *VBucketConfig) { c.RealEndpoint = "https://s3.example.com?x=1" },
		"wrong scheme":           func(c *VBucketConfig) { c.RealEndpoint = "ftp://s3.example.com" },
		"zero endpoint port":     func(c *VBucketConfig) { c.RealEndpoint = "https://s3.example.com:0" },
		"large endpoint port":    func(c *VBucketConfig) { c.RealEndpoint = "https://s3.example.com:65536" },
		"text endpoint port":     func(c *VBucketConfig) { c.RealEndpoint = "https://s3.example.com:abc" },
		"empty endpoint port":    func(c *VBucketConfig) { c.RealEndpoint = "https://s3.example.com:" },
		"empty endpoint host":    func(c *VBucketConfig) { c.RealEndpoint = "https://:443" },
		"vhost ipv4 endpoint":    func(c *VBucketConfig) { c.RealEndpoint, c.RealUsePathStyle = "http://127.0.0.1:9000", false },
		"vhost ipv6 endpoint":    func(c *VBucketConfig) { c.RealEndpoint, c.RealUsePathStyle = "http://[::1]:9000", false },
		"encoded endpoint path":  func(c *VBucketConfig) { c.RealEndpoint = "https://s3.example.com/%2F" },
		"empty endpoint query":   func(c *VBucketConfig) { c.RealEndpoint = "https://s3.example.com?" },
		"bad bucket":             func(c *VBucketConfig) { c.RealBucket = "Bad_Bucket" },
		"missing access":         func(c *VBucketConfig) { c.RealAccessKey = "" },
		"missing secret":         func(c *VBucketConfig) { c.RealSecretKey = "" },
		"missing region":         func(c *VBucketConfig) { c.RealRegion = "" },
		"invalid region":         func(c *VBucketConfig) { c.RealRegion = "us-east-1\r\nInjected" },
		"invalid access":         func(c *VBucketConfig) { c.RealAccessKey = "access key" },
		"comma access":           func(c *VBucketConfig) { c.RealAccessKey = "access,key" },
		"equals access":          func(c *VBucketConfig) { c.RealAccessKey = "access=key" },
		"invalid secret":         func(c *VBucketConfig) { c.RealSecretKey = "secret\nInjected" },
		"dot prefix":             func(c *VBucketConfig) { c.PathPrefix = "tenant/../other" },
		"empty segment":          func(c *VBucketConfig) { c.PathPrefix = "tenant//other" },
		"backslash prefix":       func(c *VBucketConfig) { c.PathPrefix = `tenant\other` },
		"control prefix":         func(c *VBucketConfig) { c.PathPrefix = "tenant/evil\x7f" },
		"unicode control prefix": func(c *VBucketConfig) { c.PathPrefix = "tenant/evil\u0085" },
		"invalid utf8 prefix":    func(c *VBucketConfig) { c.PathPrefix = "tenant/" + string([]byte{0xff}) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := validTestVBucketConfig()
			mutate(config)
			_, err := NormalizeVBucketConfig(config)
			require.Error(t, err)
		})
	}
	_, err := NormalizeVBucketConfig(nil)
	require.Error(t, err)
}
