package http_server

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpaqueRoutingTokensAreDeterministicDomainSeparatedAndAuthenticated(t *testing.T) {
	config := &VBucketConfig{RealEndpoint: "https://origin-a.example.com", RealBucket: "real-bucket", PathPrefix: "tenant-a", RoutingTokenKey: testRoutingTokenKey}

	first, err := encodeOpaqueToken(config, "upload", "origin-token")
	require.NoError(t, err)
	second, err := encodeOpaqueToken(config, "upload", "origin-token")
	require.NoError(t, err)
	assert.Equal(t, first, second, "stable origin IDs need stable virtual IDs")
	assert.NotContains(t, first, "origin-token")

	continuation, err := encodeOpaqueToken(config, "continuation", "origin-token")
	require.NoError(t, err)
	assert.NotEqual(t, first, continuation)

	otherPrefix := *config
	otherPrefix.PathPrefix = "tenant-b"
	otherPrefixToken, err := encodeOpaqueToken(&otherPrefix, "upload", "origin-token")
	require.NoError(t, err)
	assert.NotEqual(t, first, otherPrefixToken)

	otherKey := *config
	otherKey.RoutingTokenKey = []byte("abcdef0123456789abcdef0123456789")
	otherKeyToken, err := encodeOpaqueToken(&otherKey, "upload", "origin-token")
	require.NoError(t, err)
	assert.NotEqual(t, first, otherKeyToken)

	decoded, err := decodeOpaqueToken(config, "upload", first)
	require.NoError(t, err)
	assert.Equal(t, "origin-token", decoded)
	_, err = decodeOpaqueToken(config, "continuation", first)
	require.Error(t, err)
	_, err = decodeOpaqueToken(&otherPrefix, "upload", first)
	require.Error(t, err)
	_, err = decodeOpaqueToken(&otherKey, "upload", first)
	require.Error(t, err)

	replacement := "A"
	if first[len(first)-1:] == replacement {
		replacement = "B"
	}
	tampered := first[:len(first)-1] + replacement
	_, err = decodeOpaqueToken(config, "upload", tampered)
	require.Error(t, err)
	_, err = decodeOpaqueToken(config, "upload", "origin-token")
	require.Error(t, err)
	_, err = encodeOpaqueToken(config, "upload", "")
	require.Error(t, err)

	tokenCipher, err := newOpaqueTokenCipher(config)
	require.NoError(t, err)
	noncanonicalNonce := make([]byte, tokenCipher.aead.NonceSize())
	sealed := tokenCipher.aead.Seal(append([]byte(nil), noncanonicalNonce...), noncanonicalNonce, []byte("origin-token"), opaqueTokenAAD(config, "upload"))
	noncanonical := "vb1.upload." + base64.RawURLEncoding.EncodeToString(sealed)
	_, err = decodeOpaqueToken(config, "upload", noncanonical)
	require.Error(t, err, "a valid AEAD envelope with a non-synthetic nonce is not a canonical routing ID")
}

func TestOpaqueRoutingTokensDoNotSurviveStorageNamespaceRetarget(t *testing.T) {
	original := &VBucketConfig{
		RealEndpoint:    "https://origin-a.example.com",
		RealBucket:      "real-bucket",
		PathPrefix:      "tenant-a",
		RoutingTokenKey: testRoutingTokenKey,
	}
	token, err := encodeOpaqueToken(original, "upload", "origin-upload-id")
	require.NoError(t, err)

	retargeted := *original
	retargeted.RealEndpoint = "https://origin-b.example.com"
	_, err = decodeOpaqueToken(&retargeted, "upload", token)
	require.Error(t, err, "endpoint binding must reject old IDs even before the control-plane-required key rotation")
}
