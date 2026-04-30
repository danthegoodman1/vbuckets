package env

import (
	"os"
	"strconv"
	"time"
)

var (
	Env                    = os.Getenv("ENV")
	Env_TracingServiceName = os.Getenv("TRACING_SERVICE_NAME")
	Env_OLTPEndpoint       = os.Getenv("OLTP_ENDPOINT")

	HTTPListenAddress = GetEnvOrDefault("HTTP_ADDRESS", ":8080")
	ControlPlaneURL   = os.Getenv("CONTROL_PLANE_URL") // e.g. "localhost:9090" -- gRPC address of the control plane

	SigV4MaxClockSkew = GetEnvOrDefaultDuration("SIGV4_MAX_CLOCK_SKEW", 15*time.Minute)

	ControlPlaneSecurityMode    = GetEnvOrDefault("CONTROL_PLANE_SECURITY_MODE", "insecure")
	ControlPlaneTLSCAFile       = os.Getenv("CONTROL_PLANE_TLS_CA_FILE")
	ControlPlaneTLSServerName   = os.Getenv("CONTROL_PLANE_TLS_SERVER_NAME")
	ControlPlaneTLSCertFile     = os.Getenv("CONTROL_PLANE_TLS_CERT_FILE")
	ControlPlaneTLSKeyFile      = os.Getenv("CONTROL_PLANE_TLS_KEY_FILE")
	ControlPlaneAuthBearerToken = os.Getenv("CONTROL_PLANE_AUTH_BEARER_TOKEN")

	HTTPReadHeaderTimeout = GetEnvOrDefaultDuration("HTTP_READ_HEADER_TIMEOUT", 10*time.Second)
	HTTPIdleTimeout       = GetEnvOrDefaultDuration("HTTP_IDLE_TIMEOUT", 2*time.Minute)
	HTTPReadTimeout       = GetEnvOrDefaultDuration("HTTP_READ_TIMEOUT", 0)
	HTTPWriteTimeout      = GetEnvOrDefaultDuration("HTTP_WRITE_TIMEOUT", 0)

	UpstreamDialTimeout           = GetEnvOrDefaultDuration("UPSTREAM_DIAL_TIMEOUT", 30*time.Second)
	UpstreamTLSHandshakeTimeout   = GetEnvOrDefaultDuration("UPSTREAM_TLS_HANDSHAKE_TIMEOUT", 10*time.Second)
	UpstreamResponseHeaderTimeout = GetEnvOrDefaultDuration("UPSTREAM_RESPONSE_HEADER_TIMEOUT", 30*time.Second)
	UpstreamExpectContinueTimeout = GetEnvOrDefaultDuration("UPSTREAM_EXPECT_CONTINUE_TIMEOUT", 1*time.Second)
	UpstreamIdleConnTimeout       = GetEnvOrDefaultDuration("UPSTREAM_IDLE_CONN_TIMEOUT", 90*time.Second)
	UpstreamMaxIdleConns          = GetEnvOrDefaultInt("UPSTREAM_MAX_IDLE_CONNS", 100)
	UpstreamMaxIdleConnsPerHost   = GetEnvOrDefaultInt("UPSTREAM_MAX_IDLE_CONNS_PER_HOST", 100)

	CacheMaxCredentials = GetEnvOrDefaultInt("CACHE_MAX_CREDENTIALS", 10_000)
	CacheMaxBaseHosts   = GetEnvOrDefaultInt("CACHE_MAX_BASE_HOSTS", 10_000)
	CacheMaxVBuckets    = GetEnvOrDefaultInt("CACHE_MAX_VBUCKETS", 10_000)
)

func GetEnvOrDefault(key, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}

func GetEnvOrDefaultInt(key string, defaultValue int) int {
	if value, ok := os.LookupEnv(key); ok {
		intValue, err := strconv.Atoi(value)
		if err != nil {
			return defaultValue
		}
		return intValue
	}
	return defaultValue
}

func GetEnvOrDefaultDuration(key string, defaultValue time.Duration) time.Duration {
	if value, ok := os.LookupEnv(key); ok {
		durationValue, err := time.ParseDuration(value)
		if err != nil {
			return defaultValue
		}
		return durationValue
	}
	return defaultValue
}
