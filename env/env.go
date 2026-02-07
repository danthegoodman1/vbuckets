package env

import (
	"os"
	"strconv"
)

var (
	Env                    = os.Getenv("ENV")
	Env_TracingServiceName = os.Getenv("TRACING_SERVICE_NAME")
	Env_OLTPEndpoint       = os.Getenv("OLTP_ENDPOINT")

	HTTPListenAddress = GetEnvOrDefault("HTTP_ADDRESS", ":8080")
	ControlPlaneURL   = os.Getenv("CONTROL_PLANE_URL") // e.g. "localhost:9090" -- gRPC address of the control plane

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
