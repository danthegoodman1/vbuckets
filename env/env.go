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

	S3BaseHost = os.Getenv("S3_BASE_HOST") // e.g. "s3.example.com" for vhost detection

	VirtualAccessKeyID     = os.Getenv("VIRTUAL_ACCESS_KEY_ID")
	VirtualSecretAccessKey = os.Getenv("VIRTUAL_SECRET_ACCESS_KEY")
	VirtualBucketName      = os.Getenv("VIRTUAL_BUCKET_NAME")

	RealS3Endpoint      = os.Getenv("REAL_S3_ENDPOINT") // e.g. "s3.us-east-1.amazonaws.com"
	RealBucket           = os.Getenv("REAL_BUCKET")
	RealAccessKeyID      = os.Getenv("REAL_ACCESS_KEY_ID")
	RealSecretAccessKey  = os.Getenv("REAL_SECRET_ACCESS_KEY")
	RealRegion           = GetEnvOrDefault("REAL_REGION", "us-east-1")
	RealPathPrefix       = os.Getenv("REAL_PATH_PREFIX")                  // optional prefix to prepend to object keys
	RealUsePathStyle     = os.Getenv("REAL_USE_PATH_STYLE") == "true" // default false (vhost-style)
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
