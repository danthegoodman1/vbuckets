package http_server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const virtualOpaqueTokenVersion = "vb1"

func encodeOpaqueToken(cfg *VBucketConfig, kind, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("%s token must not be empty", kind)
	}
	tokenCipher, err := routingTokenCipher(cfg)
	if err != nil {
		return "", err
	}
	nonceMAC := hmac.New(sha256.New, tokenCipher.nonceKey)
	_, _ = nonceMAC.Write([]byte(virtualOpaqueTokenVersion + "\x00" + kind + "\x00" + value))
	nonce := nonceMAC.Sum(nil)[:tokenCipher.aead.NonceSize()]
	sealed := tokenCipher.aead.Seal(append([]byte(nil), nonce...), nonce, []byte(value), opaqueTokenAAD(cfg, kind))
	return virtualOpaqueTokenVersion + "." + kind + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func decodeOpaqueToken(cfg *VBucketConfig, kind, value string) (string, error) {
	prefix := virtualOpaqueTokenVersion + "." + kind + "."
	if !strings.HasPrefix(value, prefix) {
		return "", fmt.Errorf("%s token is not a vbuckets virtual token", kind)
	}
	encoded := strings.TrimPrefix(value, prefix)
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode virtual %s token: %w", kind, err)
	}
	if base64.RawURLEncoding.EncodeToString(data) != encoded {
		return "", fmt.Errorf("virtual %s token is not canonically encoded", kind)
	}
	tokenCipher, err := routingTokenCipher(cfg)
	if err != nil {
		return "", err
	}
	if len(data) < tokenCipher.aead.NonceSize() {
		return "", fmt.Errorf("virtual %s token is truncated", kind)
	}
	nonce, ciphertext := data[:tokenCipher.aead.NonceSize()], data[tokenCipher.aead.NonceSize():]
	plaintext, err := tokenCipher.aead.Open(nil, nonce, ciphertext, opaqueTokenAAD(cfg, kind))
	if err != nil {
		return "", fmt.Errorf("authenticate virtual %s token: %w", kind, err)
	}
	nonceMAC := hmac.New(sha256.New, tokenCipher.nonceKey)
	_, _ = nonceMAC.Write([]byte(virtualOpaqueTokenVersion + "\x00" + kind + "\x00" + string(plaintext)))
	if !hmac.Equal(nonce, nonceMAC.Sum(nil)[:tokenCipher.aead.NonceSize()]) {
		return "", fmt.Errorf("virtual %s token does not use its canonical nonce", kind)
	}
	return string(plaintext), nil
}

type opaqueTokenCipher struct {
	aead         cipher.AEAD
	nonceKey     []byte
	realBucket   string
	pathPrefix   string
	realEndpoint string
	routingKey   [32]byte
}

func routingTokenCipher(cfg *VBucketConfig) (*opaqueTokenCipher, error) {
	if cfg != nil && cfg.routingTokenCodec != nil && cfg.routingTokenCodec.matches(cfg) {
		return cfg.routingTokenCodec, nil
	}
	return newOpaqueTokenCipher(cfg)
}

func (c *opaqueTokenCipher) matches(cfg *VBucketConfig) bool {
	return cfg != nil && len(cfg.RoutingTokenKey) == len(c.routingKey) &&
		c.realBucket == cfg.RealBucket && c.pathPrefix == cfg.PathPrefix && c.realEndpoint == cfg.RealEndpoint &&
		bytes.Equal(c.routingKey[:], cfg.RoutingTokenKey)
}

func newOpaqueTokenCipher(cfg *VBucketConfig) (*opaqueTokenCipher, error) {
	if cfg == nil {
		return nil, fmt.Errorf("routing token mapping is required")
	}
	if len(cfg.RoutingTokenKey) != 32 {
		return nil, fmt.Errorf("routing token key must be exactly 32 bytes")
	}
	encKey := routingTokenSubkey(cfg, "encryption")
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	codec := &opaqueTokenCipher{
		aead:         aead,
		nonceKey:     routingTokenSubkey(cfg, "synthetic-nonce"),
		realBucket:   cfg.RealBucket,
		pathPrefix:   cfg.PathPrefix,
		realEndpoint: cfg.RealEndpoint,
	}
	copy(codec.routingKey[:], cfg.RoutingTokenKey)
	return codec, nil
}

func routingTokenSubkey(cfg *VBucketConfig, purpose string) []byte {
	mac := hmac.New(sha256.New, cfg.RoutingTokenKey)
	_, _ = mac.Write([]byte("vbuckets-routing-token-v1\x00" + purpose + "\x00" + cfg.RealEndpoint + "\x00" + cfg.RealBucket + "\x00" + cfg.PathPrefix))
	return mac.Sum(nil)
}

func opaqueTokenAAD(cfg *VBucketConfig, purpose string) []byte {
	return []byte(virtualOpaqueTokenVersion + "\x00" + purpose + "\x00" + cfg.RealEndpoint + "\x00" + cfg.RealBucket + "\x00" + cfg.PathPrefix)
}
