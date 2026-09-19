// Package env loads process configuration once, before runtime components start.
package env

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Current is process configuration. The binary must check LoadError before
// starting any server. Runtime code treats Current as read-only.
var Current, LoadError = Load(os.LookupEnv)

type LookupFunc func(string) (string, bool)
type Config struct {
	HTTP         HTTPConfig
	S3           S3Config
	Upstream     UpstreamConfig
	Cache        CacheConfig
	ControlPlane ControlPlaneConfig
}
type HTTPConfig struct {
	Address, AdminAddress                                     string
	ReadHeaderTimeout, IdleTimeout, ReadTimeout, WriteTimeout time.Duration
}
type S3Config struct{ SigV4MaxClockSkew time.Duration }
type UpstreamConfig struct {
	DialTimeout, TLSHandshakeTimeout, ResponseHeaderTimeout, ExpectContinueTimeout, IdleConnTimeout time.Duration
	MaxIdleConns, MaxIdleConnsPerHost                                                               int
}
type CacheConfig struct{ MaxCredentials, MaxBaseHosts, MaxVBuckets int }
type ControlPlaneConfig struct {
	URL, SecurityMode, TLSCAFile, TLSServerName, TLSCertFile, TLSKeyFile, AuthBearerToken string
}

func Defaults() Config {
	return Config{
		HTTP:         HTTPConfig{Address: ":8080", AdminAddress: "127.0.0.1:8081", ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute},
		S3:           S3Config{SigV4MaxClockSkew: 15 * time.Minute},
		Upstream:     UpstreamConfig{DialTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, ExpectContinueTimeout: time.Second, IdleConnTimeout: 90 * time.Second, MaxIdleConns: 100, MaxIdleConnsPerHost: 100},
		Cache:        CacheConfig{MaxCredentials: 10000, MaxBaseHosts: 10000, MaxVBuckets: 10000},
		ControlPlane: ControlPlaneConfig{SecurityMode: "insecure"},
	}
}

type durationSetting struct {
	name  string
	value *time.Duration
	zero  bool
}

func (c *Config) durations() []durationSetting {
	return []durationSetting{
		{"SIGV4_MAX_CLOCK_SKEW", &c.S3.SigV4MaxClockSkew, false},
		{"HTTP_READ_HEADER_TIMEOUT", &c.HTTP.ReadHeaderTimeout, false}, {"HTTP_IDLE_TIMEOUT", &c.HTTP.IdleTimeout, false},
		{"HTTP_READ_TIMEOUT", &c.HTTP.ReadTimeout, true}, {"HTTP_WRITE_TIMEOUT", &c.HTTP.WriteTimeout, true},
		{"UPSTREAM_DIAL_TIMEOUT", &c.Upstream.DialTimeout, false}, {"UPSTREAM_TLS_HANDSHAKE_TIMEOUT", &c.Upstream.TLSHandshakeTimeout, false},
		{"UPSTREAM_RESPONSE_HEADER_TIMEOUT", &c.Upstream.ResponseHeaderTimeout, false}, {"UPSTREAM_EXPECT_CONTINUE_TIMEOUT", &c.Upstream.ExpectContinueTimeout, false},
		{"UPSTREAM_IDLE_CONN_TIMEOUT", &c.Upstream.IdleConnTimeout, false},
	}
}

type intSetting struct {
	name  string
	value *int
}

func (c *Config) integers() []intSetting {
	return []intSetting{
		{"UPSTREAM_MAX_IDLE_CONNS", &c.Upstream.MaxIdleConns}, {"UPSTREAM_MAX_IDLE_CONNS_PER_HOST", &c.Upstream.MaxIdleConnsPerHost},
		{"CACHE_MAX_CREDENTIALS", &c.Cache.MaxCredentials}, {"CACHE_MAX_BASE_HOSTS", &c.Cache.MaxBaseHosts}, {"CACHE_MAX_VBUCKETS", &c.Cache.MaxVBuckets},
	}
}

func Load(lookup LookupFunc) (Config, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	c := Defaults()
	for _, s := range []struct {
		name  string
		value *string
	}{
		{"HTTP_ADDRESS", &c.HTTP.Address}, {"ADMIN_ADDRESS", &c.HTTP.AdminAddress},
		{"CONTROL_PLANE_URL", &c.ControlPlane.URL}, {"CONTROL_PLANE_SECURITY_MODE", &c.ControlPlane.SecurityMode},
		{"CONTROL_PLANE_TLS_CA_FILE", &c.ControlPlane.TLSCAFile}, {"CONTROL_PLANE_TLS_SERVER_NAME", &c.ControlPlane.TLSServerName},
		{"CONTROL_PLANE_TLS_CERT_FILE", &c.ControlPlane.TLSCertFile}, {"CONTROL_PLANE_TLS_KEY_FILE", &c.ControlPlane.TLSKeyFile},
		{"CONTROL_PLANE_AUTH_BEARER_TOKEN", &c.ControlPlane.AuthBearerToken},
	} {
		if value, ok := lookup(s.name); ok {
			*s.value = strings.TrimSpace(value)
		}
	}
	c.ControlPlane.SecurityMode = strings.ToLower(c.ControlPlane.SecurityMode)
	for _, s := range c.durations() {
		if value, ok := lookup(s.name); ok {
			parsed, err := time.ParseDuration(value)
			if err != nil {
				return c, fmt.Errorf("%s must be a duration", s.name)
			}
			*s.value = parsed
		}
	}
	for _, s := range c.integers() {
		if value, ok := lookup(s.name); ok {
			parsed, err := strconv.Atoi(value)
			if err != nil {
				return c, fmt.Errorf("%s must be an integer", s.name)
			}
			*s.value = parsed
		}
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.ControlPlane.URL == "" {
		return fmt.Errorf("CONTROL_PLANE_URL is required")
	}
	for name, address := range map[string]string{"HTTP_ADDRESS": c.HTTP.Address, "ADMIN_ADDRESS": c.HTTP.AdminAddress} {
		_, port, err := net.SplitHostPort(address)
		n, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || n < 0 || n > 65535 {
			return fmt.Errorf("%s must be a host:port listen address", name)
		}
	}
	for _, s := range c.durations() {
		if *s.value < 0 || (!s.zero && *s.value == 0) {
			return fmt.Errorf("%s has an invalid timeout", s.name)
		}
	}
	for _, s := range c.integers() {
		if *s.value <= 0 {
			return fmt.Errorf("%s must be positive", s.name)
		}
	}
	cp := c.ControlPlane
	switch cp.SecurityMode {
	case "insecure":
		if cp.TLSCAFile != "" || cp.TLSServerName != "" || cp.TLSCertFile != "" || cp.TLSKeyFile != "" {
			return fmt.Errorf("control-plane TLS options cannot be used in insecure mode")
		}
	case "tls":
		if cp.TLSCertFile != "" || cp.TLSKeyFile != "" {
			return fmt.Errorf("control-plane client certificate requires mtls mode")
		}
	case "mtls":
		if cp.TLSCertFile == "" || cp.TLSKeyFile == "" {
			return fmt.Errorf("control-plane mtls requires both certificate and key")
		}
	default:
		return fmt.Errorf("unsupported CONTROL_PLANE_SECURITY_MODE")
	}
	return nil
}
