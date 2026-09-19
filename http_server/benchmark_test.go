package http_server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// This benchmark can also run unchanged on main: identical signed requests,
// a precompiled allow-all policy, stubbed resolver results, and no network I/O.
// It measures authentication, planning, IAM, and dispatch, not storage throughput.
func BenchmarkS3AuthenticatedRequest(b *testing.B) {
	for _, path := range []string{"/bucket/key", "/bucket?list-type=2"} {
		b.Run(path, func(b *testing.B) {
			req, _ := http.NewRequest(http.MethodGet, "http://s3.example.com"+path, nil)
			req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
			err := awsv4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now())
			if err != nil {
				b.Fatal(err)
			}
			handler := S3Auth(newTestResolver())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNoContent {
					b.Fatal(w.Code, w.Body.String())
				}
			}
		})
	}
}
