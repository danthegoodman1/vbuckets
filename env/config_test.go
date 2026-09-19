package env

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadRejectsMalformedAndContradictoryConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		values map[string]string
	}{
		{name: "malformed duration", values: map[string]string{"CONTROL_PLANE_URL": "cp:9090", "SIGV4_MAX_CLOCK_SKEW": "later"}},
		{name: "nonpositive cache", values: map[string]string{"CONTROL_PLANE_URL": "cp:9090", "CACHE_MAX_CREDENTIALS": "0"}},
		{name: "negative timeout", values: map[string]string{"CONTROL_PLANE_URL": "cp:9090", "UPSTREAM_DIAL_TIMEOUT": "-1s"}},
		{name: "mtls without pair", values: map[string]string{"CONTROL_PLANE_URL": "cp:9090", "CONTROL_PLANE_SECURITY_MODE": "mtls", "CONTROL_PLANE_TLS_CERT_FILE": "cert.pem"}},
		{name: "insecure with TLS options", values: map[string]string{"CONTROL_PLANE_URL": "cp:9090", "CONTROL_PLANE_SECURITY_MODE": "insecure", "CONTROL_PLANE_TLS_CA_FILE": "ca.pem"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(mapLookup(tt.values))
			require.Error(t, err)
		})
	}
}

func TestLoadUsesOneDocumentedDefaultSetAndReturnsAnImmutableValue(t *testing.T) {
	values := map[string]string{"CONTROL_PLANE_URL": "cp:9090"}
	cfg, err := Load(mapLookup(values))
	require.NoError(t, err)
	require.Equal(t, ":8080", cfg.HTTP.Address)
	require.Equal(t, 15*time.Minute, cfg.S3.SigV4MaxClockSkew)
	require.Equal(t, 10_000, cfg.Cache.MaxCredentials)
	require.Equal(t, "insecure", cfg.ControlPlane.SecurityMode)

	values["HTTP_ADDRESS"] = ":9999"
	require.Equal(t, ":8080", cfg.HTTP.Address, "configuration must not read the environment after Load")
}

func mapLookup(values map[string]string) LookupFunc {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestValidateRejectsInvalidConstructedValues(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.Cache.MaxCredentials = 0 },
		func(c *Config) { c.Upstream.DialTimeout = -time.Second },
		func(c *Config) { c.HTTP.AdminAddress = "bad-address" },
		func(c *Config) { c.S3.SigV4MaxClockSkew = 0 },
	} {
		cfg := Defaults()
		cfg.ControlPlane.URL = "cp:9090"
		change(&cfg)
		require.Error(t, cfg.Validate())
	}
	cfg := Defaults()
	cfg.ControlPlane.URL = "cp:9090"
	require.NoError(t, cfg.Validate())
	require.Equal(t, "127.0.0.1:8081", cfg.HTTP.AdminAddress)
}
