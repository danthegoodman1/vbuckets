package http_server

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Retains the review's focused benchmark for comparison with 88c65e8.
func BenchmarkGetPlanAndAuthorization(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/bucket/key", nil)
	b.ReportAllocs()
	for b.Loop() {
		plan, err := planS3Operation(req, "bucket", "key")
		if err != nil {
			b.Fatal(err)
		}
		plan = plan.withRequestMetadata(false, "").withAuthorizationContext("", time.Now())
		if err := AuthorizeS3Plan(testAllowAllPolicy, plan); err != nil {
			b.Fatal(err)
		}
	}
}

// No network and no object-sized fixture: compare allocation growth as the
// streamed body grows 64-fold. Throughput here is only the in-process copy loop.
func BenchmarkObjectStreaming(b *testing.B) {
	for _, size := range []int64{1 << 20, 64 << 20} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/bucket/key", nil)
			plan := &S3OperationPlan{kind: operationGetObject, responseProfile: responseStreamObject, bucket: "bucket", objectKey: "key"}
			cfg := &VBucketConfig{}
			w := discardResponse{header: make(http.Header)}
			b.SetBytes(size)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(io.LimitReader(benchmarkZeros{}, size))}
				if err := writeVirtualizedUpstreamResponse(w, req, resp, plan, cfg, ""); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

type benchmarkZeros struct{}

func (benchmarkZeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type discardResponse struct{ header http.Header }

func (w discardResponse) Header() http.Header       { return w.header }
func (discardResponse) WriteHeader(int)             {}
func (discardResponse) Write(p []byte) (int, error) { return len(p), nil }
