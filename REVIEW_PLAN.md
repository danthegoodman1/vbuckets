# Architecture and Correctness Review Plan

Reviewed 2026-09-19 on `architecture-hardening`, committed baseline `88c65e8`, including the uncommitted `env/env.go`, `env/config_test.go`, `domain/`, and `http_server/phase4_regression_test.go`.

The scoped implementation and subsequent simplification pass are complete. `PLAN.md` was used only for historical context. F1–F5, F7, and F8 are resolved; F6 now catches up on the existing stream, while conservative failures under unrelated global churn remain an explicit accepted limitation. Evidence below is from the integrated working tree, not prior plan claims.

## Overarching Goal

Fix the demonstrated authorization, isolation, and transfer-completion defects with the smallest understandable changes. Keep useful redesigns when they directly solve those defects; do not turn this review into a general platform or performance project.

Keep the validated S3 operation plan, compiled IAM policies, bounded caches, miss admission, mapping-scoped tokens, and revisioned watch. They enforce real requirements. Remove the unused domain copies and inbound gRPC/h2c path. Keep startup validation, health-route separation, and final request freshness validation, but use ordinary Go code and the existing synchronization state. Package-layer purity, a generic request-decision system, and zero failures under arbitrary control-plane churn are not release requirements.

## Findings and Evidence

Priorities: P1 = address before release; P2 = important behavior or operational correction. This table records findings as reviewed, with line references to baseline `88c65e8` and the original dirty draft. Historical probes assert the defects; corrected regressions and current completion evidence are in the phase ledgers.

| ID | Priority | Finding and consequence | Concrete evidence |
| --- | --- | --- | --- |
| F1 | P1 | **Forwarding changes security-relevant headers after IAM evaluation.** A PutObject with `x-amz-server-side-encryption: AES256` and `Connection: x-amz-server-side-encryption` satisfies an IAM encryption condition, but the outbound header is removed. The resulting origin request does not have the semantics IAM approved. The same boundary affects other conditional headers. | `http_server/s3_operation.go:154` snapshots all headers; `http_server/iam.go:127` uses that snapshot; `http_server/s3_proxy.go:362` later removes Connection-nominated headers. `TestReviewConnectionNominationChangesAuthorizedEncryption` reproduced an allow followed by an absent outbound encryption header. |
| F2 | P1 | **Credential revocation can be observed before IAM runs, yet the request still succeeds.** Credentials/policy are fetched first, mapping is fetched later, and authorization uses the retained policy without a final freshness check. Slow bounded control-body reads can enlarge this interval. This is earlier than the documented exemption for requests whose authorization has already completed. | `http_server/s3_middleware.go:104`, `:156`, `:203`, `:211`; The HTTP pipeline does not revalidate freshness before completing authorization. `TestReviewCredentialRevocationBeforeIAMStillAuthorizes` applied a real Client credential-removal event during mapping resolution: a subsequent credential lookup returned not-found, but the S3 middleware invoked its authorized handler. |
| F3 | P1 | **A failed streamed download can become a successful truncated object.** A response-copy error is logged and the handler returns normally, allowing normal downstream completion when the origin length is unknown. | `http_server/s3_response.go:83` and `http_server/s3_proxy.go:300`. A real chunked origin sent 8,192 bytes and aborted; `TestReviewBrokenChunkedDownloadReturnsCleanEOF` observed downstream HTTP 200 and `io.ReadAll` error `nil`. Late list-transform errors use the same return path. |
| F4 | P1 | **The unconditional h2c wrapper buffers unauthenticated upgrade bodies.** It sits outside S3 authentication and has no body-size bound, contrary to the streaming design. The application does not register an inbound gRPC service. | `http_server/server.go:64` through `:81`; `main.go` passes a nil gRPC server. `TestReviewH2CReadsBodyBeforeAuthentication` confirmed 4 MiB read before the router/auth handler was entered. The pinned `golang.org/x/net@v0.49.0/http2/h2c` implementation calls `io.ReadAll(r.Body)` during upgrade; the [Go package documentation](https://pkg.go.dev/golang.org/x/net/http2/h2c#NewHandler) describes this buffering. |
| F5 | P2 | **Administrative routes occupy valid S3 object names.** Virtual-hosted GETs for keys `hc` and `ready` return health JSON without reaching S3 authentication or object routing. | `http_server/server.go:57`. `TestReviewHealthPathsShadowVirtualHostedObjects` reproduced both collisions with host `bucket.s3.example.com`. Most proxy integration tests mount `RegisterS3Routes` directly, so they omit this production wrapper. |
| F6 | P2 | **Unrelated global revisions can starve cold lookups; a valid ahead-of-watch unary result disconnects the whole proxy.** Each lookup requires exact global-revision equality even if intervening invalidations concern other keys. Two unrelated events can exhaust the one retry. A newer unary revision triggers reconnect instead of bounded catch-up on the healthy stream. This couples tenant availability to global write traffic. | `controlplane/lookup.go:36`, `:42`, `:145`, `:319`; `controlplane/watch.go:42`. `TestReviewUnrelatedWatchChurnRejectsColdCredentials` generated one unrelated event per RPC: an unchanged credential failed after two calls while the client remained synchronized. Ahead-of-watch disconnection is established by the code and existing `TestFutureUnaryEvidenceRecordsRequiredRevisionBeforePayloadParsing`. |
| F7 | P2 | **Resolver outages and admission rejection are presented as identity/permission failures.** Credential failures mostly become 403 `InvalidAccessKeyId`; mapping failures become 403 `AccessDenied`. Callers receive the wrong retry semantics even though the cache correctly avoids caching service failures. | `http_server/s3_middleware.go:105` and `:204`; `controlplane/errors.go` already distinguishes several operational causes. The draft `domain/errors.go` and phase-4 regression test point in the right direction but are not wired into production. |
| F8 | P1 | **The dirty refactor is not a viable integration unit and introduces duplicate authority.** Removing environment globals breaks their existing consumers. The new domain package duplicates the resolver types, IAM condition schema, mapping validation, and token cryptography without production adoption. Copies already differ: the draft mapping accepts any printable real access key, while the active validator uses the bounded access-key grammar. | Working-tree `go test ./...` fails on undefined `env.UpstreamDialTimeout`, `env.SigV4MaxClockSkew`, and other removed globals. `http_server/phase4_regression_test.go` also references absent `S3Dependencies` and `writeCredentialLookupError`. Compare `domain/mapping.go:62` with `http_server/vbucket.go`; compare both policy files. `TestReviewConfigValidationGaps` additionally proved the draft accepts `NaN`/`+Inf` miss rates, and direct `Config.Validate()` accepts zero capacity and negative timeout. |

F6 remains a real availability limitation, but the reproduction does not establish its frequency in a deployment. This plan fixes unnecessary reconnects and retry semantics. Fine-grained invalidation tracking is deferred; conservative retryable rejection during concurrent updates is acceptable for now. The safety guarantees are unchanged.

### Review Validation

An isolated `git archive HEAD` copy at `/private/tmp/vbuckets-review.980255` was used to avoid changing the dirty tree. Review probes reside only there in `http_server/review_probe_test.go`, `controlplane/review_probe_test.go`, and `review_env/review_probe_test.go`; these temporary artifacts may eventually be removed by the OS. The scenarios in the findings table are the durable reproduction specifications.

- Original committed baseline: `go test ./... -short -count=1` passed.
- Isolated committed code plus six reproduction probes: `go test ./... -count=1` passed, including Garage Docker integration tests; `go test -race ./... -short -count=1` and `go vet ./...` passed.
- Copied draft configuration only: `go test ./review_env -run '^TestReview' -v -count=1` confirmed the F8 validation gaps.
- A minimal GetObject planning/authorization benchmark measured approximately 3.7–4.3 microseconds, 5,236–5,237 bytes, and 67 allocations per request on an Apple M3 Max, Go 1.26.0. This excludes signature verification, resolver calls, network I/O, and response processing; it is an optimization lead, not a production throughput claim.
- Protocol regeneration/breaking checks were not run during this review. No protocol or generated files changed. Existing plan claims are not substituted for current verification.

## Implementation Principles

- Preserve isolation, exact operation/IAM correspondence, fail-closed revocation, mapping-bound tokens, and streaming bodies. Already-authorized streams retain the existing lifetime exemption.
- Prefer deleting an unused feature, rejecting an ambiguous request, or adding a small check to introducing a new abstraction.
- Keep the current package structure. Sharing a few resolver errors at the existing interface boundary is sufficient; HTTP operation plans, policy tables, mapping validation, and token codecs do not need another home.
- Use the existing revision, epoch, readiness state, and catch-up target. Do not introduce dependency graphs, per-request registrations, pinned cache entries, invalidation journals, or new wire APIs.
- A final global freshness check is deliberately conservative: concurrent unrelated updates can cause a 503. Accept that tradeoff until a measured workload justifies finer tracking. Never hold locks across I/O or add transparent request replay.
- Complete each change with its focused regression. Do not require new TLS modes, multiple independently configured instances, universal dependency injection, or a broad load-testing framework.

## Testing Strategy

- Convert the demonstrated bugs into focused regressions. Use the production server wrapper for listener/routing cases and real HTTP clients for transfer-abort cases.
- Test invalidation, disconnect, and credential rotation at the request's final freshness boundary, including a delayed bounded XML body. Existing watch-state tests cover the underlying state machine.
- Keep the existing contract, IAM, namespace, token, and Garage tests. Final gates are `go test ./... -count=1`, `go test -race ./... -short -count=1`, and `go vet ./...`.
- No protobuf changes are planned. Run protocol checks if implementation actually changes those files.
- Use the existing request microbenchmark and one focused streaming check to catch regressions. A performance redesign requires evidence of a bottleneck; a comprehensive benchmark campaign is not part of this plan.

## Phase 1: Restore the Build and Remove Duplicate Implementations

Goal:
Resolve F8 without adopting the unfinished architecture wholesale.

Scope:
- Keep a single startup load/validation boundary for settings the binary actually uses, and wire its existing consumers in the same change. Per-process configuration and a shared upstream HTTP client are acceptable; eliminating all globals is not a goal.
- Validate supported settings once at startup. Reject malformed/nonpositive values, nonfinite rates if rates are configurable, and inconsistent transport options. Do not add unused settings or new configuration modes to complete the draft structs.
- Remove the unused `domain/` copies rather than migrate the working implementation into them. Retain the active mapping validator, IAM schema, token codec, and resolver interface in their current owners. Port useful error tests in Phase 3 and remove tests that only prescribe nonexistent helper APIs.

Completion gate:
The actual working tree builds, has one implementation of each responsibility, and rejects invalid supported startup configuration. No general dependency-injection or package migration is required.

Testing plan:
Cover startup defaults and invalid supported settings, then run the short suite and vet. Preserve behavior tests; remove scaffolding for features dropped from scope.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | 1A: Restore compiling startup configuration and consumers | `env/env.go` loads one supported process config; `main.go` validates it before listeners start; all consumers compile. |
| Complete | Work | 1B: Validate the settings actually supported | `env/config_test.go`: defaults, malformed durations, nonpositive capacities/timeouts, listen addresses, and inconsistent TLS settings. Built-binary smoke test rejects missing URL, zero capacity, and unreadable CA. |
| Complete | Work | 1C: Remove unused domain copies and placeholder scaffolding | Removed unreferenced `domain/` copies and placeholder `phase4_regression_test.go`; retained active `http_server/vbucket.go`, `iam.go`, and token codec; useful regressions live in `env/config_test.go` and `http_server/boundary_test.go`. |
| Complete | Test | 1T: Startup tests, short suite, and vet | `go test ./... -count=1`, `go test -race ./... -short -count=1`, and `go vet ./...` pass after integration and simplification. |
| Complete | Gate | 1G: Buildable baseline without duplicate implementations | Integrated working tree builds (`go build .`); configuration tests pass; no duplicate domain implementation remains. |

## Phase 2: Fix Listener Isolation and Stream Aborts

Goal:
Resolve F3–F5 with standard HTTP server behavior.

Scope:
- Delete the unused inbound gRPC multiplexer and unconditional h2c upgrade wrapper. Keep ordinary `net/http`; do not replace the removed feature with another protocol framework or impose a global object-body cap.
- Move health/readiness to one small administrative `http.Server` with a configurable listen address and ordinary bounded shutdown. Keep this redesign: every path can be an object key on a virtual-hosted bucket, so renaming the health paths would merely move the collision. Do not build an administrative service framework.
- Abort the downstream transfer on errors in the two already-committed streaming paths: object copying and list rewriting. Keep existing sanitized pre-commit errors. Use [the `http.ErrAbortHandler` mechanism](https://pkg.go.dev/net/http#ErrAbortHandler) and verify the current recovery middleware propagates it; no general response-lifecycle state machine is needed.
- Document the administrative probe address and existing TLS/SecureTransport behavior. Adding native TLS or trusted-forwarder modes is deferred; do not weaken forwarded-header rejection to make a draft test pass.

Completion gate:
Upgrade requests cannot buffer bodies ahead of authentication, health routes cannot shadow S3 objects, and a failed origin stream cannot become a cleanly completed download.

Testing plan:
Run the F3–F5 probes as corrected regressions through the production wrapper. Check normal streaming, client cancellation, and shutdown; retain existing successful-transfer tests. Assert a real client read failure for truncated chunked downloads.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | 2A: Delete unused inbound gRPC/h2c support | `http_server/server.go` uses ordinary `http.Server`; `TestUnauthenticatedH2CUpgradeDoesNotReadBody` proves zero reads before authentication. |
| Complete | Work | 2B: Minimal separate health/readiness listener | `TestAdminRoutesDoNotShadowS3Objects` covers virtual-hosted `hc`/`ready` and readiness status. Built-binary smoke test verifies distinct listeners and clean SIGTERM closure of both. `README.md` documents `ADMIN_ADDRESS`. |
| Complete | Doc | 2C: Document existing transport semantics | `README.md` states actual-connection SecureTransport semantics, unsupported forwarded headers, ordinary inbound HTTP, and outbound-only control-plane TLS settings. |
| Complete | Work | 2D: Abort errors from committed streaming branches | `TestFailedStreamingResponseAbortsClientTransfer` observes failed object/list reads over HTTP/1.1 and HTTP/2; `http.ErrAbortHandler` propagates through the production recovery middleware. |
| Complete | Test | 2T: Production-wrapper streaming, cancellation, and routing regressions | `TestSuccessfulLargeObjectStreamsBeforeOriginCompletes` transfers 32 MiB with bytes observable before origin completion; `TestClientCancellationClosesOriginStream` and routing/abort tests pass. Streaming allocation evidence: `PERFORMANCE.md`. |
| Complete | Gate | 2G: Isolated health routes and honest transfer completion | F3–F5 regressions pass through `NewServer`; two standard servers replace the custom server/gRPC/h2c wrapper. |

## Phase 3: Add Small Authorization Boundary Checks

Goal:
Resolve F1, F2, and F7 without a new request-decision subsystem.

Scope:
- Reject requests that use `Connection` to nominate a forwarded end-to-end header. Put this check in existing request validation before IAM. The existing operation plan remains the request representation; no second normalization pipeline is needed.
- Read the existing global `(revision, epoch)` while ready before any credential/host/mapping resolution. After body parsing, signature verification, and IAM evaluation, atomically check readiness and that same pair immediately before dispatch. Make this the authorization completion point. Expose only a small required resolver check/stamp API; do not register handles, pin entries, or track dependency lists.
- If the final check fails, return retryable 503 and stop. Apply it to origin operations, CreateBucket, and ListBuckets. Add no automatic replay or new retry loop; the existing bounded lookup retry need not be expanded. Preserve confirmed Create success after dispatch.
- Translate resolver errors once at the existing interface boundary. Distinguish not-found/denied, temporary failure, throttling, and invalid upstream response with a few errors and a small HTTP switch. Map temporary failures to 503, admission rejection to 503 `SlowDown`, and invalid upstream data to sanitized 502; retain current identity/permission denials for actual not-found/denied results. Do not mirror the entire gRPC error taxonomy or create a domain package for it.

Completion gate:
Headers relied on by IAM reach the origin unchanged except for intentional routing/signing rewrites; a request cannot complete authorization using state invalidated before the final check; transient failures are retryable. Unrelated updates may conservatively reject an otherwise valid request.

Testing plan:
Use one signed Connection-nomination regression plus a small header table. Cover credential revocation/rotation, mapping invalidation, and disconnect before the final check, including delayed control XML and create/list paths. Test HTTP error categories and retain service-failure/negative-cache separation.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | 3A: Reject semantic header removal | `TestConnectionCannotRemoveAuthorizedHeaders` covers nominated semantic headers and a signed SSE-conditioned PutObject rejected before mapping/forwarding. |
| Complete | Work | 3B: Small global revision/epoch check at the resolver boundary | Required `Resolver.BeginResolution` / `ValidateResolution` use the existing revision and epoch under `syncMu`; no handles or tracked requests. `TestResolutionStampRetiresWhenSameRevisionReconnects` covers epoch retirement. |
| Complete | Work | 3C: Final check on origin/create/list dispatch | `TestRequestCannotAuthorizeAcrossControlPlaneChanges` covers removal, rotation, mapping change, disconnect, object/list dispatch, and Create/Complete XML reads. Existing confirmed-Create-success regressions still pass. |
| Complete | Work | 3D: Minimal resolver-to-HTTP error translation | `TestResolverErrorsPreserveHTTPMeaning` exercises credentials, host, mapping, create, list, and both freshness boundaries; `TestResolverErrorClassification` covers wrapped RPC/context causes. Existing negative-cache separation tests pass. |
| Complete | Test | 3T: Focused authorization, race, and error regressions | Full and race suites pass, including the new real Client invalidation tests and signed HTTP regressions. |
| Complete | Gate | 3G: Safe authorization boundary with explicit conservative failures | `S3Auth` has one IAM/freshness/dispatch path for every operation; regressions prove rejection before dispatch. `README.md` records the conservative 503 tradeoff. |

## Phase 4: Reuse Existing Watch Catch-Up; Defer Fine-Grained Tracking

Goal:
Reduce the avoidable outage in F6 without promising zero false rejections under global churn.

Scope:
- When a unary response reports a revision ahead of the watch, reuse the `requiredRevision` and `StateSynchronizing` behavior already used by CreateVBucket. Let the healthy stream catch up within its existing synchronization deadline. Do not add a waiter registry, retained response queue, or new timers; the current caller may receive a retryable 503.
- Preserve the highest observed target even when the future payload is malformed. Keep snapshots, barriers, epoch retirement, and real stream/protocol fault handling intact. Do not treat older invalid responses as benign catch-up.
- Keep exact global-revision checks for now, including the final request check in Phase 3. Document the availability tradeoff. Defer per-key generations, active-load invalidation tracking, and a stronger unrelated-churn availability guarantee until an actual workload demonstrates a material problem.

Completion gate:
A future unary result does not unnecessarily tear down a healthy watch; readiness remains false below the required target; existing timeout and fault behavior remain intact. F6's unrelated-churn rejection is explicitly deferred, not reported as fixed.

Testing plan:
Adapt existing future-unary tests to assert same-stream catch-up, highest-target retention, and timeout/fault behavior. Keep the unrelated-churn reproduction as evidence of the accepted limitation; no 0/100/1,000-event load matrix is required.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Doc | 4A: Document conservative global-revision semantics | `README.md` defines the final authorization boundary, epoch retirement, same-stream catch-up, and unrelated-churn 503 limitation. |
| Complete | Decision | 4B: Fine-grained invalidation tracking — deferred | Decision recorded in scope and `README.md`: retain exact global checks; no per-key validity tracking without deployment evidence. This is a completed scope decision, not implementation of the deferred feature. |
| Complete | Work | 4C: Reuse existing bounded catch-up | `checkUnaryRevision` reuses `requiredRevision` and `StateSynchronizing`; `TestFutureUnaryCatchesUpOnSameStreamOrTimesOut` proves one stream, readiness recovery, and timeout despite heartbeats. |
| Complete | Test | 4T: Focused future-revision and fault regressions | Adapted `TestFutureUnaryEvidenceRecordsRequiredRevisionBeforePayloadParsing` verifies malformed payload evidence, highest target, no reconnect signal, and unchanged absolute start time; existing protocol/stream fault tests pass. |
| Complete | Gate | 4G: No gratuitous reconnect for valid future revisions | Same-stream and timeout tests pass; unrelated global churn rejection remains explicitly accepted and is not reported as fixed. |

## Phase 5: Verify the Fixes and Stop

Goal:
Close the scoped findings without turning qualification into another engineering project.

Scope:
- Run the existing full suite, race checks, and vet after integrating the fixes. Carry forward only the focused new regressions described above.
- Compare the existing request microbenchmark before/after and check that a large successful object still streams with bounded memory. Do not build a general load framework or tune allocations without evidence of a material regression.
- Update the affected startup, health-listener, error, and freshness documentation. Leave cloning, repeated mapping normalization, current package dependencies, and admission tuning alone unless the implementation reveals a concrete problem.

Completion gate:
F1–F5, F7, and F8 are fixed; F6's avoidable reconnect is fixed and its remaining churn limitation is documented. Existing tests and focused regressions pass. No claim of full F6 resolution or production throughput qualification is made.

Testing plan:
Run `go test ./... -count=1`, `go test -race ./... -short -count=1`, and `go vet ./...`; compare the existing benchmark and successful-transfer behavior. Repeat or broaden checks only to investigate a failure or material regression.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Test | 5A: Existing benchmark and focused streaming check | `PERFORMANCE.md` and four raw result files record seven-sample main/pre-fix/final comparisons, actual stamp-check overhead, and constant streaming allocations at 1/64 MiB. Real 32 MiB streaming regression passes. |
| Complete | Decision | 5B: Broader performance work — deferred | Decision recorded: no per-key tracking, allocation redesign, or admission retuning. `PERFORMANCE.md` reports measured deltas and limitations; broader qualification remains deferred. |
| Complete | Doc | 5C: Document changed behavior and retained limitations | `README.md` covers startup validation, admin probes, response aborts, error categories, authorization completion, catch-up, and retained limitations. |
| Complete | Work | 5D: Post-implementation simplification pass | `S3Auth` now has one authorization/freshness/dispatch path; unused custom request-ID middleware removed; `go mod tidy` only demotes UUID to indirect. Full and race suites pass before and after this pass. |
| Complete | Test | 5T: Full suite, race checks, and vet | After simplification: `go test ./... -count=1` (including Garage Docker integration), `go test -race ./... -short -count=1`, `go vet ./...`, and `make proto-check` pass. `make proto-breaking` intentionally reports the documented legacy v1 migration against main. |
| Complete | Gate | 5G: Scoped fixes verified; deferred work remains explicit | F1–F5/F7/F8 corrected regressions pass; same-stream F6 catch-up passes; remaining churn limitation documented. Final measurements and qualification are in `PERFORMANCE.md`. |

## Phase 6: Prove Per-Key IAM and Document Provisioning

Goal:
Make the existing per-access-key enforcement explicit and verifiable for shared
vbuckets, without adding another policy engine or authorization RPC.

Scope:
- Reuse the existing credential policy field, compiled evaluator, caches, and
  revisioned invalidation. Give the integration fixture separate identities and
  bucket inventories, and share its production HTTP/gRPC harness with Garage.
- Add executable policy examples and a control-plane provisioning/update
  contract. The production policy store and issuer are external to this repo;
  the in-memory single-watch fixture is not a production control-plane service.
- Prove independent key permissions, virtual resource scope, compound actions,
  and replacement of a warmed policy through the real watch.

Completion gate:
Denials occur before any origin call; keys sharing a vbucket retain independent
policies; an observed update retires the old policy; documentation explains
atomic persistence/publication and the existing revocation limits. No new
runtime authorization machinery or wire API is introduced.

Testing plan:
Run the conformance test in the short/race suites, retain Garage coverage, and
verify generated-code consistency and compatibility with the previous PR head.
Deliberately bypass IAM in an isolated copy to confirm the tests detect it.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | 6A: Multi-key and multi-bucket enforcement proof | `TestPerKeyIAMConformance` exercises two policies from `examples/iam/*.json`, initial/warm credentials, explicit deny, prefixes, copy source/destination, multipart, ACL/tagging, and per-key bucket inventory. Denied requests assert zero origin calls. |
| Complete | Work | 6B: Live policy replacement | The conformance test updates the fixture policy and revision atomically, observes the real watch invalidation, asserts exactly one credential reload for the changed key, retains the other key's cache, and restores access. Invalid updates preserve the old policy and revision. |
| Complete | Doc | 6C: Provisioning and shared namespace contract | `examples/iam/README.md`, main README, and proto comments explain one effective policy per key, virtual resource names, shared mappings for keys of one vbucket, durable publication, separate bucket inventory, and revocation limits. Production storage remains external. |
| Complete | Test | 6T: Regression, race, and protocol gates | `go test ./... -count=1` (Garage included), `go test -race ./... -short -count=1`, `go vet ./...`, and `make proto-check` pass. Compatibility against the prior `architecture-hardening` commit (`efeaea2`) passes; generated changes are comments only. |
| Complete | Gate | 6G: Existing enforcement verified without another runtime layer | Runtime request code and protobuf fields/RPCs are unchanged. A temporary copy with the IAM check bypassed fails the new conformance test because forbidden requests return 200, demonstrating that origin behavior cannot conceal missing proxy enforcement. |
