# vbuckets Development Plan

## Overarching Goal

Make vbuckets a fail-closed, streaming S3 virtualization boundary: a client-authorized virtual operation must be the same operation sent upstream, configured real bucket/endpoint/prefix identifiers may not escape through S3 protocol metadata, tenant prefixes must contain every supported operation, and control-plane state must have explicit, enforceable freshness semantics.

Keep the current strengths—streaming object bodies, bounded/streaming list rewriting, compiled IAM policies, per-key TTLs, and singleflight lookups. Do not expand the S3 surface until the supported subset is exact and testable. Replace the README's impossible absolute “no stale windows” claim with a measurable guarantee: observed revisions never regress, stream gaps force fail-closed resynchronization, and revocation latency is bounded by documented stream failure detection rather than cache TTL.

## Review Findings Driving Priority

| ID | Priority | Finding | Evidence |
| --- | --- | --- | --- |
| F1 | P0 | S3 operation detection is blacklist- and branch-order-based, so unknown or ambiguous query shapes can be authorized as a different supported action. For example, object `PUT ?retention` falls through to `s3:PutObject`, while an unknown bucket `GET` query is treated as `s3:ListBucket`. | `http_server/iam.go:88-208`; `http_server/s3_list_rewrite.go:10-37`; this contradicts `README.md:46-50,76-77`. No exhaustive query-shape test exists. |
| F2 | P0 | Prefix virtualization is operation-incomplete. Every non-ListObjects request gets the prefix inserted into the path, which misroutes bucket-level `HeadBucket` and `ListMultipartUploads`; multipart success documents, upstream errors, and redirects are passed through without virtualizing real bucket/key/endpoint fields. | `http_server/s3_proxy.go:168-256`; `http_server/s3_list_rewrite.go:10-24`; multipart actions are advertised at `README.md:62-75`. Existing proxy tests cover only ListObjects and CopyObject. |
| F3 | P0 | SigV4 verification does not require `host` in `SignedHeaders`, does not bind the credential date/service strictly to S3 request metadata, and canonicalizes a signed header with `Header.Get` while forwarding every value. This creates request-integrity and interoperability gaps for host changes, duplicate headers, and whitespace/multi-value canonicalization. | `http_server/s3_auth.go:38-81,89-130,190-255`; `http_server/s3_proxy.go:202-224,290-310`. Current tests exercise normal AWS SDK signatures but not adversarial canonicalization. |
| F4 | P1 | Malformed IAM condition operands are accepted at parse time. Invalid bool/null/numeric/date values merely fail (or change) evaluation later, so a malformed explicit `Deny` can become ineffective despite the documented “malformed policies are rejected” guarantee. | `iam/policy.go:219-317,557-699`; tests cover valid operators but not invalid typed operands in deny statements. |
| F5 | P0 | The delta protocol cannot provide the advertised cache guarantee: it has no revision, resume cursor, initial synchronization barrier, or gap detection, and the client retains caches across stream reconnects. Public random access-key misses are not negatively cached; `LookupBaseHost` also caches attacker-influenced full hostnames even though the underlying base-domain set is small. | `api/v1/controlplane.proto:94-143`; `controlplane/client.go:55-118,322-425`; `controlplane/cache.go:28-54`; claim at `README.md:107-115`. |
| F6 | P1 | The public Go API is internally inconsistent and generation is not reproducible: `go_package` declares `/api/v1`, generated files live in `/v1`, production imports `/v1`, and the repository does not pin Buf. `buf lint` failed in this review with local Buf 1.34.0 (`STANDARD` unknown). | `api/v1/controlplane.proto:3-5`; `buf.gen.yaml`; `controlplane/client.go:25`; `v1/controlplane.pb.go:5`. There were no Git tags at review time, so correcting v1 in place is preferred before release. |
| F7 | P1 | External configuration and control-plane mappings are not validated as a boundary. Invalid environment values silently become defaults, parsed endpoint errors are discarded, health is always green, gRPC calls have no proxy-owned deadline, and most control-plane failures are reported as invalid credentials/access denied instead of retryable service failures. | `env/env.go:9-70`; `http_server/s3_proxy.go:192-224,259-287`; `http_server/server.go:107-109`; `http_server/s3_middleware.go:102-110,178-183`. |
| F8 | P2 | Package ownership and globals obscure the core model and impede isolated performance tests: `controlplane` imports domain types from `http_server`, config is package-global, the upstream client is global, and a second unused request-ID middleware keeps an unnecessary production dependency. | `controlplane/cache.go:8-25`; `controlplane/client.go:13,24`; `http_server/s3_proxy.go:18-37`; `http_server/middleware.go`; `http_server/server.go:31-35`. |

## Implementation Principles

- Decode a request once into a typed operation plan; authentication, IAM checks, upstream rewriting, and response virtualization must consume that same plan.
- Permit exact supported method/query/header shapes and reject unknown, conflicting, or newly introduced subresources until explicitly implemented.
- Treat control-plane responses, environment variables, HTTP headers, URLs, and upstream responses as validation boundaries; return controlled errors rather than panic or silently reinterpret input.
- Preserve streaming for unbounded object data. Buffer only bounded control/error XML where doing so is necessary to prevent partial or leaking responses.
- Make freshness and availability tradeoffs explicit. A disconnected or gap-detected authorization/configuration watch is not “healthy.”
- Prefer one small domain/core package with inward dependencies; avoid renames or abstractions that do not remove a demonstrated inconsistency.
- Optimize from benchmark and load evidence. Protect the control plane from adversarial miss cardinality before micro-optimizing local string or XML code.

## Testing Strategy

- Add table-driven and fuzz tests for the request grammar, SigV4 canonicalization, IAM parsing, URL/path preservation, and response transforms.
- Maintain two integration layers: deterministic `httptest` upstream/control-plane fault tests and Garage end-to-end tests for real S3 SDK behavior.
- Model control-plane synchronization as a state machine and test lookup/delta races, disconnects, missed removals, reconnect barriers, and monotonic revisions under `-race`.
- Add benchmarks/load tests for warm-cache request planning, credential miss storms, large streaming objects, large list responses, and reconnect recovery; record CPU, allocations, memory high-water mark, upstream connection reuse, and control-plane QPS.
- Pin tool versions and require formatting, vet/static analysis, unit tests, race tests, protobuf lint/breaking checks, generated-code cleanliness, and end-to-end tests in CI.

## Phase 0: Make the Contract and Toolchain Executable

Goal:
Turn the intended guarantees and supported S3 subset into one reviewable contract before changing behavior, and repair the public protobuf/Go package layout while v1 is still untagged.

Scope:

- Define an operation matrix covering exact method, path class, allowed query keys/combinations, relevant headers/body, IAM actions/resources, outbound rewrite, and response transform for every advertised action.
- Define the virtual-namespace invariant for successful responses, errors, redirects, multipart fields, and headers.
- Replace the absolute cache claim with revision, stream-gap, readiness, revocation-latency, and fail-closed semantics that Phase 3 can enforce.
- Generate v1 Go code into `api/v1` so filesystem path, `go_package`, imports, and documentation agree; remove `/v1` only after imports migrate.
- Pin Buf and protoc plugin versions, add lint/generate-diff/breaking checks, and document the supported Go toolchain.

Out of scope:

- Adding new S3 operations or preserving an untagged incorrect `/v1` import path at the cost of a second permanent API location.

Completion gate:
Every advertised operation has an exact matrix row and test identifier; the README states enforceable guarantees; generated code is clean under pinned tools and imports from `github.com/danthegoodman1/vbuckets/api/v1`.

Testing plan:

- Run `buf lint`, `buf generate`, a clean-tree generated diff check, and `buf breaking` against the main branch.
- Run the full Go suite after moving generated code and imports.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Test | Current functional baseline | `GOCACHE=/private/tmp/vbuckets-go-full go test ./... -count=1` passed on 2026-08-06, including Garage-backed tests. |
| Complete | Test | Current race baseline | `GOCACHE=/private/tmp/vbuckets-go-race go test -race ./... -short -count=1` passed on 2026-08-06. |
| Complete | Test | Current vet baseline | `GOCACHE=/private/tmp/vbuckets-go-vet go vet ./...` passed on 2026-08-06. |
| Complete | Work | 0A: Operation and response contract matrix | `README.md` defines the Phase 1/2 target as 21 exact `C-S3-*` request/IAM/rewrite rows and 10 response profiles, while explicitly documenting current gaps; `TestS3OperationContract` is the executable identifier index. |
| Complete | Decision | 0B: Enforceable cache guarantee | `README.md` removes “no stale windows,” identifies current v1 as best-effort, and defines monotonic revision, barrier, gap/readiness, fail-closed, negative-cache, and measured revocation semantics for Phase 3. |
| Complete | Work | 0C: Canonical v1 Go package | Generated files and all imports now use `github.com/danthegoodman1/vbuckets/api/v1`; `TestGeneratedGoPackageMatchesCanonicalImportPath` failed on the old `/v1` location and passes after migration. |
| Complete | Tooling | 0D: Reproducible protobuf/static-analysis toolchain | Make targets pin Buf v1.72.0 and Go plugins v1.36.11 revision 1 / v1.6.1 revision 1; `proto-check` lints and compares isolated generation, and `proto-breaking` checks `main`. The existing Go vet gate remains documented; Staticcheck is unchanged and outside this protobuf-focused phase. |
| Complete | Gate | Contract and generated API are executable | `make proto-check`, `make proto-breaking`, focused contract/layout tests, `go test ./... -count=1` (including Garage E2E), `go vet ./...`, and `go test -race ./... -short -count=1` passed on 2026-08-06. |

## Phase 1: Build One Fail-Closed Request and Authorization Core

Goal:
Ensure a request is authenticated, decoded, authorized, and rewritten as one immutable typed operation, eliminating divergent interpretations and fail-open query handling.

Scope:

- Introduce a small core model (`OperationKind`, virtual resource, exact query/header/body semantics, IAM checks, request rewrite, response transform kind) and replace independent context strings with one typed request plan.
- Replace query blacklists and branch-order detection with exact per-operation allowlists; reject unknown keys, duplicate singleton keys, conflicting subresources, unsupported headers/trailers, and ambiguous multipart shapes.
- Harden SigV4 parsing/canonicalization: require and bind `host`, `x-amz-date`, `s3`, scope date, terminator, sorted unique signed headers, all canonical header values, normalized whitespace, and constant-form signature fields.
- Explicitly reject or correctly own session-token and streaming-signature modes rather than forwarding partially supported authentication metadata.
- Validate IAM condition operand types and allowed operator/key pairings during policy compilation so malformed allow and deny statements are rejected consistently.
- Return a typed unsupported/malformed/authentication error from the core and translate it once to S3-compatible status/code/message at the HTTP edge.

Out of scope:

- Presigned-query authentication, SigV4 streaming chunks, new IAM features, or new S3 operations.

Completion gate:
No bucket-mapping resolution, IAM decision, or upstream request occurs without one exact operation plan, every plan has all required IAM checks, and all unknown/ambiguous shapes fail before proxying. The credential lookup needed to authenticate the request remains the intentional pre-plan exception.

Testing plan:

- Add exhaustive tables generated from the Phase 0 matrix, including `PUT ?retention`, unknown bucket queries, conflicting multipart keys, unsupported object-lock/KMS forms, and duplicate query keys.
- Add AWS SigV4 reference vectors plus adversarial tests for missing host, altered host, duplicate/multi-value headers, whitespace, scope/date/service mismatch, unsigned trailers, and session tokens.
- Fuzz authorization-header parsing, raw path/query decoding, operation planning, copy-source parsing, and IAM policy parsing; assert no panic and fail-closed output.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | 1A: Typed immutable operation plan | `S3OperationPlan` is built once with private operation, virtual resource, original query, defensive header/query snapshots, body kind/control bytes, IAM checks/context, parsed copy-source metadata, and response profile. Middleware, IAM, dispatch, and proxy consume plan-owned values; mutation tests prove the request and returned IAM contexts cannot alter it. |
| Complete | Work | 1B: Exact operation grammar | `TestS3OperationContract` covers all 21 rows and matrix-derived matching/mismatched/duplicate `x-id`, unknown-query, allowed-query, body-kind, streaming, and header-combination tables. Empty rows reject known and chunked/unknown bodies; CreateBucket and CompleteMultipart XML are bounded/parsed before mapping; directive/checksum/SSE-C/ACL conflicts and unsupported object-lock/KMS forms fail closed. Invalid shapes fail before `LookupVBucket` in `TestS3Auth_UnsupportedShapeFailsBeforeVBucketLookup`. |
| Complete | Work | 1C: Strict SigV4 envelope | Adversarial tests prove required host/date coverage, canonical signed-header order/uniqueness, scope binding, fixed service/terminator/signature forms, authentication-header singleton rules, altered host rejection, and AWS SDK-compatible whitespace/all-value canonicalization. |
| Complete | Work | 1D: Explicit unsupported auth/header modes | Session tokens, signed trailers, SigV4 streaming payloads, multipart-copy headers, KMS-specific inputs, and object-lock inputs return a controlled unsupported request error; ordinary unsigned-payload SDK and Garage flows remain green. |
| Complete | Work | 1E: Compile-time IAM operand validation | `TestParsePolicyJSONRejectsMalformedTypedConditionOperands` proves malformed explicit-deny bool/null/numeric/date values are rejected; S3 policy compilation also rejects operator/key type mismatches. |
| Incomplete | Work | 1F: Typed S3 error taxonomy | Request-shape/authentication classes now have one HTTP-edge translation (`InvalidRequest`, auth-specific SigV4 errors, or authorization denial). Not-found, unavailable, and upstream/control-plane failure classification remains in Phase 4 scope. |
| Complete | Test | 1G: Exhaustive, adversarial, and fuzz coverage | Matrix, request-body/header rejection, immutability, AWS signer-oracle, policy, middleware-boundary, and fuzz seed suites cover F1/F3/F4. Raw-path namespace and response properties remain assigned to Phase 2. |
| Complete | Gate | Authorized operation equals forwarded operation | IAM checks/context and downstream method, headers, content length/body kind, raw query, copy/list metadata, and response profile come from the same defensive plan. `go test ./... -count=1`, `go vet ./...`, and `go test -race ./... -short -count=1` passed on 2026-08-06, including Garage and control-plane E2E. |

## Phase 2: Enforce the Virtual Namespace in Both Directions

Goal:
Make path-prefix isolation and whitelabeling true for every supported request and every client-visible response, not only single-object paths and successful ListObjects responses.

Scope:

- Make request rewriting operation-specific: keep bucket operations at bucket root; scope ListObjects and ListMultipartUploads query fields; rewrite object/multipart/copy keys without losing raw-path semantics.
- Add response transform handlers keyed by `OperationKind` for ListObjects, ListMultipartUploads, CreateMultipartUpload, ListParts, CompleteMultipartUpload, CopyObject where needed, and all supported S3 error documents.
- Rewrite or synthesize client-visible `Bucket`, `Key`, `Prefix`, markers, `Location`, endpoint, and redirect/header fields so real identifiers cannot escape.
- Strip RFC hop-by-hop headers, including names nominated by `Connection`, and define safe trailer behavior before outbound signing and on the response path.
- Validate and normalize control-plane mapping fields before production cache insertion and defensively at the public Resolver adapter: endpoint scheme/host/port policy, bucket, region, path prefix, addressing style, routing-token key, and credential presence. Moving to an immutable validated domain type and removing redundant adapter parsing is Phase 4 ownership work.
- Preserve constant-memory streaming for object bodies and large lists; buffer only size-capped control/error XML when atomic validation/redaction is required.

Out of scope:

- Blindly passing through an upstream operation or response schema that is not in the Phase 0 matrix.

Completion gate:
Two virtual buckets sharing one real bucket cannot list, address, or infer each other's prefixes through any supported operation, and no success/error/redirect fixture exposes configured real endpoint, bucket, or path-prefix sentinels.

Testing plan:

- Add shared-backend integration tests for HeadBucket and the complete multipart lifecycle, including concurrent uploads in two tenant prefixes and pagination/markers.
- Add response-leak tests using unique sentinel endpoint/bucket/prefix values across success, 3xx, 4xx, and 5xx responses and headers.
- Add escaped-key/property tests for spaces, `+`, `%`, encoded slash, Unicode, repeated slashes, empty keys, and path-style/vhost-style combinations.
- Measure allocations and memory high-water mark for large object and list streams; inject malformed/truncated upstream XML and client cancellation.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | 2A: Operation-specific request transforms | All 21 operation kinds map exhaustively to bucket-root, list-query, or object-path transforms. HeadBucket/ListMultipartUploads remain at the real root; marker/start-after/prefix fields and opaque routing IDs are operation-specific. Unknown transforms fail closed. |
| Complete | Work | 2B: Multipart namespace isolation | R6-R9 request/response transforms cover bucket/key/prefix/marker/location and the create, part, list, complete, abort lifecycle. Continuation/upload/version IDs use authenticated mapping-scoped `vb1` tokens; stable keys survive replicas/restarts/credential rotation but MUST change on endpoint/bucket/prefix retarget. |
| Complete | Work | 2C: Error/redirect/header virtualization | One declarative per-profile semantic-field table drives schema admission, transforms, exact request echoes, required fields, conditional markers, and identity containers. Bounded XML is atomic; large lists stream scalar-atomically. Compatible finite standard S3 error codes are preserved with generic messages, unknown codes synthesize safely, redirects become 502, 304 is empty, and Owner/Initiator are virtual identities. |
| Complete | Work | 2D: Proxy header/trailer sanitation | Outbound and response headers use operation/profile allowlists; RFC hop-by-hop plus `Connection` nominations are removed, unsupported trailers fail closed, response header validation stages atomically, transformed/discarded representations drop stale length/encoding/checksum validators, and transport decompression is disabled. |
| Complete | Work | 2E: Validated backend mapping | Control-plane lookup/create/delta insertion validates and clones endpoint/bucket/credential/region/prefix/addressing/key fields; the public mutable Resolver DTO is defensively revalidated at the proxy boundary. IP endpoints require path style. An immutable domain mapping type that removes redundant hot-path validation remains Phase 4 debt. |
| Complete | Test | 2F: Cross-tenant and no-leak integration suite | Concurrent two-tenant shared-backend multipart lifecycle/pagination tests cover HeadBucket, escaped keys, cross-tenant token replay before origin, success profiles R3-R10, safe 3xx/304/4xx/5xx handling, header collisions, owner identities, mapping retarget, invalid mappings, and exact echo mismatches. |
| Complete | Test | 2G: Streaming and cancellation proof | Large list streaming, truncated/malformed/mixed/nested/foreign XML, bounded control/error documents, writer cancellation, and stored-gzip byte identity are covered. Final M3 Max 1,000-item benchmarks (2026-08-06) measured ~1.17 ms/38.4 MB/s/606 KB/20,033 allocs for plain lists and ~1.54 ms/35.2 MB/s/727 KB/25,044 allocs for `encoding=url`. The reproducible 1,000-upload token benchmark improved from ~3.76 ms/4.63 MB/62,042 allocs to ~2.59 ms/2.00 MB/45,042 allocs by reusing one mapping codec; repeated defensive normalization retains that codec at ~854 ns/554 B/7 allocs. Further allocation reduction is Phase 4 optimization work. |
| Complete | Gate | Complete virtual namespace | On 2026-08-06, final post-review `GOCACHE=/private/tmp/vbuckets-phase2-final3 go test ./... -count=1` passed including Garage E2E, `GOCACHE=/private/tmp/vbuckets-phase2-vet3 go vet ./...` passed, and `GOCACHE=/private/tmp/vbuckets-phase2-race3 go test -race ./http_server -short -count=1` passed after the last R6 marker change; the preceding complete-tree race gate `GOCACHE=/private/tmp/vbuckets-phase2-race2 go test -race ./... -short -count=1` also passed. `make proto-check` and `make proto-breaking` passed. The non-disclosure guarantee applies to proxy-owned protocol metadata; object bytes and user-controlled object metadata remain intentionally byte-transparent. |

## Phase 3: Make Control-Plane Freshness Monotonic and Miss Load Bounded

Goal:
Replace best-effort unversioned cache deltas with a gap-detecting synchronization protocol, and prevent public miss cardinality from becoming unbounded control-plane load.

Scope:

- Extend the pre-release v1 contract with monotonic revisions/cursors on lookup results and watch events plus an explicit watch synchronization barrier.
- On disconnect or a detected gap, mark the client unsynchronized, fail readiness, clear/retire affected cached state, and do not serve authorization/routing decisions until a new watch barrier is established.
- Make cache writes revision-aware so an older unary result or event can neither replace nor be returned after a newer revision has been observed.
- Represent found/not-found plus separate positive/negative TTLs for credentials and vbuckets; cache legitimate negative results while never caching unavailable/internal failures.
- Replace per-request full-hostname lookup/cache entries with a versioned local base-domain set and deterministic longest-suffix matching.
- Add proxy-owned unary RPC deadlines, exponential backoff with jitter, explicit connection/sync state, and bounded admission/rate controls for novel credential IDs.
- Expose cache hit/miss/negative-hit/eviction/load-coalescing metrics, watch revision/gap/reconnect state, RPC latency/status, and rejected-miss counts without logging secrets.

Out of scope:

- Claiming zero propagation delay or serving stale authorization state for availability after the watch is known to be unsynchronized.

Completion gate:
A deterministic fault suite proves no revision regression, missed removal, stale post-barrier lookup result, or unbounded RPC amplification across disconnect/reconnect and randomized invalid-key traffic.

Testing plan:

- Build a controllable fake control plane with revisions, blocked unary calls, watch gaps, duplicates, reordering attempts, disconnects, and snapshot/barrier events.
- Add race/model tests for delta-versus-loader interleavings and property tests asserting monotonic returned revisions.
- Load-test repeated and random invalid access keys; assert configured bounds on control-plane QPS, in-flight lookups, memory, and recovery latency.
- Add process-level readiness tests for startup, synced, disconnected, resynchronizing, and shutdown states.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Incomplete | Work | 3A: Revisioned lookup/watch protocol | Gap: F5; current messages have no revision, cursor, barrier, or gap signal. |
| Incomplete | Work | 3B: Fail-closed synchronization state machine | Gap: `controlplane.Client` retains caches while the watch reconnects on a fixed five-second loop. |
| Incomplete | Work | 3C: Monotonic cache wrapper | Missing: revision comparison spanning unary loaders, events, invalidation, and in-flight callers. |
| Incomplete | Work | 3D: Negative credential/vbucket caching | Missing: found/not-found values and control-plane-selected negative TTLs; random invalid keys currently invoke loaders repeatedly. |
| Incomplete | Work | 3E: Local base-domain registry | Gap: `LookupBaseHost` and its cache are keyed by each request hostname rather than the small registered domain set. |
| Incomplete | Work | 3F: Deadlines, jittered retry, and miss admission | Missing: proxy-owned gRPC deadline and bounded novel-key load. |
| Incomplete | Work | 3G: Cache/watch observability and readiness | Gap: `/hc` always reports 200 and exposes no synchronization state. |
| Incomplete | Test | 3H: State-machine, race, and adversarial-load suite | Missing: disconnect/removal/reconnect, revision race, negative-cache, and random-key flood evidence. |
| Incomplete | Gate | Bounded revocation and miss amplification | Missing: measured revocation/recovery bound and maximum control-plane QPS under the agreed load profile. |

## Phase 4: Validate Operations, Simplify Ownership, and Qualify Performance

Goal:
Make startup and failure behavior predictable, reduce cross-package coupling, and prove that the hardened design keeps the streaming proxy efficient under realistic load.

Scope:

- Replace package-global environment reads with `Config.Load`/`Validate` at startup; reject malformed, non-positive, or contradictory values and inject immutable config into server, resolver, caches, signer, and transport.
- Decide and implement the inbound transport model (built-in TLS or explicitly trusted TLS terminator) so `aws:SecureTransport` reflects authenticated deployment reality rather than accidental topology.
- Map control-plane `NotFound`/permission failures separately from timeout/unavailable/internal failures and return retryable S3/HTTP errors where appropriate.
- Move credentials, mappings, revisions, resolver contracts, and operation plans into the core/domain package; keep HTTP and gRPC adapters pointing inward.
- Inject clock and upstream transport/client dependencies, remove the unused custom request-ID middleware and dependency, and remove or justify the unused co-hosted gRPC/h2c server path.
- Add concurrency/backpressure limits only where load evidence shows a bound is needed; preserve connection reuse and streaming.
- Document deployment, security modes, readiness, limits, supported operations, and control-plane migration before release.

Out of scope:

- Pure package renames, speculative framework adoption, or micro-optimizations without benchmark evidence.

Completion gate:
Invalid startup/config/mapping inputs fail deterministically without panic; outages produce correct retry semantics and readiness; package dependencies point inward; and agreed throughput/latency/memory/control-plane-QPS budgets pass with no regression in tenant/auth guarantees.

Testing plan:

- Add config and mapping validation tables/fuzzers, TLS-terminator tests, gRPC status/deadline tests, startup/readiness tests, and malformed upstream/control-plane payload tests.
- Establish reproducible benchmarks before refactoring, rerun after each subphase, and profile only measured regressions.
- Run full unit, race, vet/static-analysis, protobuf, Garage end-to-end, fault, leak-sentinel, and load suites as the release gate.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Incomplete | Work | 4A: Parsed, validated, injected configuration | Gap: F7/F8; invalid integers and durations silently use defaults and global values are read throughout packages. |
| Incomplete | Decision | 4B: Inbound TLS/trusted-proxy model | Missing: deployment contract ensuring `aws:SecureTransport` is trustworthy behind a terminator. |
| Incomplete | Work | 4C: Retry-aware control-plane error mapping | Gap: lookup failures collapse to `InvalidAccessKeyId` or `AccessDenied` in `S3Auth`. |
| Incomplete | Work | 4D: Inward package dependency graph | Gap: `controlplane` imports `http_server` for domain models and IAM policy parsing. |
| Incomplete | Work | 4E: Injectable clock and upstream transport | Missing: deterministic timeout, signing-time, cancellation, connection, and upstream fault tests without globals. |
| Incomplete | Work | 4F: Remove proven dead/generic surface | Evidence: `http_server.RequestID` is unused while Chi's middleware is registered; co-hosted gRPC is unused by `main.go`. Missing: cleanup after dependency migration. |
| Incomplete | Test | 4G: Performance and resource baseline | Missing: benchmark/load artifacts for warm hits, cold/negative misses, large streams, concurrent tenants, and control-plane recovery. |
| Incomplete | Doc | 4H: Release and migration documentation | Missing: supported matrix, v1 import migration, freshness semantics, readiness, TLS model, and resource limits. |
| Incomplete | Gate | Production qualification | Missing: pinned-tool CI evidence plus agreed SLO/resource budgets and all correctness/security suites passing. |
