# Performance and qualification

Measured on 2026-09-19 with Go 1.26.0, darwin/arm64, Apple M3 Max, `-cpu=1`.
Numbers below are medians of seven 1-second samples, run sequentially for each
snapshot. They are local microbenchmarks, not production throughput estimates or
latency guarantees. Small timing differences should be treated as run variation.

## Comparable request costs

The identical `http_server/benchmark_test.go` was copied into isolated archives
of main (`8c6a2df6a4593d00629c3ae4cf5d7d6cc0547d52`) and the pre-fix branch
(`88c65e814015c888613d5625f7efbef9e49a09ab`). Final is the implementation in this PR
after its simplification pass. All cases verify the same pre-signed SigV4 GET,
use a precompiled allow-all IAM policy and stub resolver results, and dispatch
to a no-content handler. Request signing is outside the timer. The benchmark
includes signature verification, request parsing/planning, IAM, and dispatch;
it excludes real control-plane/cache work, network I/O, and response processing.

| Workload | Main | Pre-fix branch | Final | Final vs main | Final vs pre-fix |
| --- | ---: | ---: | ---: | ---: | ---: |
| GetObject | 7.804 µs | 18.206 µs | 18.214 µs | +133.4% | +0.04% |
| ListObjectsV2 | 8.808 µs | 19.962 µs | 19.781 µs | +124.6% | −0.91% |

| Workload | Main B/op; allocs/op | Pre-fix B/op; allocs/op | Final B/op; allocs/op |
| --- | ---: | ---: | ---: |
| GetObject | 6,568; 111 | 12,050; 170 | 12,050; 170 |
| ListObjectsV2 | 7,832; 125 | 13,762; 191 | 13,762; 191 |

The full branch has a material CPU/allocation cost versus main: about 2.3× the
request CPU time, +83.5% GetObject bytes and +75.7% listing bytes. This is already
present in `88c65e8`, before the scoped fixes. Main lacks the branch's exact
operation validation and immutable request/IAM snapshots, so it is a weaker
correctness baseline. These measurements do not establish which individual
hardening mechanism dominates the cost; no unsupported attribution or production
performance improvement is claimed. The scoped fixes add no allocations here.

The review's planning/IAM-only benchmark (no signature verification) changes
from 6.024 µs to 5.712 µs (−5.2%), with 5,232 B/op and 67 allocs/op in both.
Treat that timing difference as indicative, not a promised optimization.

The HTTP comparison's stub resolver does not measure the new real Client locks.
`BenchmarkReadyResolutionStamp` separately measures `BeginResolution` plus
`ValidateResolution`: **11.63 ns/op, zero bytes and allocations**, with no writer
contention. It does not qualify performance under watch churn or many CPUs.

## Streaming allocation bound

`BenchmarkObjectStreaming` generates bytes incrementally and discards output;
there is no object-sized fixture, network, TLS, or storage backend. Its purpose
is to detect allocation growth with body size. Its reported MB/s is only an
in-process copy loop and must not be interpreted as proxy/storage throughput.

| Body | Pre-fix | Final | Final timing delta | B/op, both | Allocs/op, both |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 MiB | 10.954 µs | 9.374 µs | −14.4% | 33,112 | 6 |
| 64 MiB | 339.726 µs | 334.317 µs | −1.6% | 33,112 | 6 |

Allocations stay constant as body size grows 64-fold. Successful copy code was
not optimized; the timing differences are not a claimed streaming speedup.
The real-network `TestSuccessfulLargeObjectStreamsBeforeOriginCompletes`
additionally transfers 32 MiB and verifies that the client receives bytes while
the origin is still waiting to produce the remainder. This is a bounded-memory
streaming check, not a general load test.

## Reproduction and raw results

```sh
go test ./http_server -run '^$' \
  -bench '^(BenchmarkS3AuthenticatedRequest|BenchmarkGetPlanAndAuthorization|BenchmarkObjectStreaming)$' \
  -benchmem -benchtime=1s -count=7 -cpu=1
go test ./controlplane -run '^$' -bench '^BenchmarkReadyResolutionStamp$' \
  -benchmem -benchtime=1s -count=7 -cpu=1
```

For main, copy only `http_server/benchmark_test.go` and run only
`BenchmarkS3AuthenticatedRequest`: the other request/streaming helpers were
introduced by the hardening branch. For `88c65e8`, also copy
`http_server/plan_benchmark_test.go` and run the first command. The stamp benchmark
exists only in the final implementation.

Raw Go output: [main](benchmarks/results/2026-09-19-main.txt),
[pre-fix branch](benchmarks/results/2026-09-19-before.txt),
[final](benchmarks/results/2026-09-19-final.txt),
[real stamp checks](benchmarks/results/2026-09-19-stamp.txt).

## Correctness qualification

Passed after implementation and the simplification pass:

- `go test ./... -count=1`, including Garage Docker integration tests.
- `go test -race ./... -short -count=1`.
- `go vet ./...` and `go build .`.
- `make proto-check`: pinned lint and regeneration with no generated-code drift.
- Built-binary smoke test: missing control-plane URL, zero cache capacity, and
  unreadable TLS CA fail startup; separate S3/admin listeners return the expected
  authentication/liveness/readiness responses; SIGTERM exits successfully and
  closes both listening ports.

The integration fixture subsequently moved from Garage to digest-pinned
S3Proxy 4.0.0. This changes only test setup; the production request path and
the benchmarks above are unchanged.

`make proto-breaking` **fails intentionally against main**: this branch replaces
legacy `ListenForDeltas` / `LookupBaseHost`, removes sensitive pushed mapping and
credential fields, and makes CreateVBucket revision-only. No protocol changes
were added by the scoped review fixes. The complete PR requires the coordinated
pre-release migration documented in README; `make check` is not reported as green.

Remaining limits: exact global revisions may reject requests during unrelated
updates; already-authorized streams are not cancelled by later revocation.
Fine-grained invalidation tracking and broad performance tuning remain deferred.
