# vbuckets

Infinite virtual S3 buckets - Serve unlimited S3 buckets and credentials on top of one or more physical S3 buckets.

Implemented as an S3-compatible reverse proxy that maps virtual buckets and credentials to real S3 backends.

Designed for whitelabeling -- give tenants their own bucket names, access keys, and IAM policies without exposing your underlying storage.

```
+-----------+     +----------+     +-----------+
| S3 Client |---->| vbuckets |---->|  Real S3  |
+-----------+     |  proxy   |     +-----------+
                  +----+-----+
                       |
                 +-----+------+
                 |   Your     |
                 |   Control  |
                 |   Plane    |
                 +------------+
```

Clients connect with virtual credentials and virtual bucket names. vbuckets verifies the SigV4 signature (including request-time skew checks), resolves the virtual bucket to a real backend (bucket, endpoint, region, credentials, optional path prefix), checks IAM permissions, then re-signs and proxies the request. Incoming requests must use `x-amz-content-sha256: UNSIGNED-PAYLOAD` so uploads can stream through the proxy without buffering. SigV4 signed-header names must be lowercase, sorted, and unique; `host` and `x-amz-date` are required, all values of a signed header are canonicalized and verified, and any other `x-amz-*` request header except `x-amz-content-sha256` must also be signed. `CreateBucket` and `ListBuckets` are intercepted by vbuckets and sent to the control plane instead of the origin service. Supports both virtual-hosted (`bucket.s3.example.com/key`) and path-style (`s3.example.com/bucket/key`) addressing in both directions.

Credential issuers must use virtual access-key IDs matching
`[A-Za-z0-9._-]{1,128}`. The same bounded grammar is enforced before a key can
reach control-plane/cache lookup or synthesized XML.

## Lookup functions

The auth middleware is split into two phases. Credentials and mappings use
revisioned unary lookups; request hosts are matched locally against the
watch-owned base-domain registry:

| Lookup | Input | Returns |
|---|---|---|
| `LookupCredentials` | access key ID | secret key, IAM policy, TTL |
| Local base-domain match | request hostname | longest registered base-domain suffix |
| `LookupVBucket` | access key ID + bucket name | real endpoint, bucket, region, path prefix, addressing style, stable routing-token key, TTL |
| `CreateVBucket` | access key ID + bucket name + location constraint | committed global revision |
| `ListVBuckets` | access key ID | visible virtual bucket names and creation dates |

The local base-domain match determines whether an incoming request is
virtual-hosted style (`bucket.s3.example.com`) or path style
(`s3.example.com/bucket`). `WatchState` supplies the bounded normalized-domain
set, and matching probes DNS-label suffixes longest-first without creating
attacker-controlled per-host cache entries.

**Phase 1 (authentication)** runs `LookupCredentials` and verifies the SigV4 signature before any bucket resolution happens. **Phase 2 (authorization)** resolves the request shape and checks IAM permissions. Object and bucket-object operations use the local base-domain registry plus `LookupVBucket` before proxying. `CreateBucket` uses `CreateVBucket`, and `ListBuckets` uses `ListVBuckets`; neither operation is forwarded to the origin service.

## Target S3 operation and virtualization contract

This matrix is the enforced acceptance and virtualization contract. Requests
are decoded once into a typed operation plan; unknown, duplicate, conflicting,
or operation-mismatched query/header shapes fail before virtual bucket mapping
or IAM evaluation. The same plan selects the exact outbound path/query rewrite,
safe request headers, response schema, request-echo checks, required response
fields, and namespace transforms.

The supported request surface is deliberately exact. A request uses only one row;
unknown query keys, duplicate singleton keys, conflicting subresources or
headers, unexpected bodies, or operation-changing headers not named by that row
are unsupported. `X`
means no operation query or exactly one `x-id` whose value names that AWS
operation. Every other query key shown is a singleton. A flag such as `uploads`
must occur once with an empty value. The stable `C-S3-*` identifiers and their
currently valid representative shapes are checked by
[`TestS3OperationContract`](./http_server/s3_contract_test.go).
Numeric pagination and part fields must contain an in-range decimal integer;
`fetch-owner` is `true` or `false`, and the only supported `encoding-type` is
`url`. `max-uploads` is 1 through 1000. Empty R6 marker elements are accepted
for an initial nontruncated listing, but actual multipart upload IDs remain
nonempty authenticated tokens.

The signing headers described above are required on
every row. Ordinary HTTP content, range, and conditional headers are allowed
where their HTTP method uses them, as are signed `x-amz-meta-*` object metadata
headers. ACL/grant, tagging, copy, storage-class, and server-side-encryption
headers affect an operation and are accepted only where called out below.
`Connection` cannot nominate a forwarded end-to-end header: the origin must
receive the header semantics that IAM approved. Session tokens, KMS-specific and object-lock request forms, signed/checksummed
trailers, and SigV4 streaming chunks are rejected as unsupported.

An empty-body row requires a zero content length and rejects chunked or
otherwise unknown-length bodies. `CreateBucketConfiguration` and
`CompleteMultipartUpload` XML are each capped at 1 MiB and parsed before any
bucket mapping or upstream request; object, part, ACL, and tagging body rows
remain streaming. Operation headers are singletons unless their family is
explicitly repeatable. Canned ACLs cannot be combined with grant headers.
SSE-C requires its AES256 algorithm, key, and key-MD5 tuple and cannot be
combined with SSE-S3. Fixed checksum values are supported for PutObject,
UploadPart, and CompleteMultipartUpload, while CreateMultipartUpload may select
the checksum algorithm; multiple or inconsistent checksum families are rejected.

| ID | Virtual operation | Exact method/path and allowed query | Relevant headers/body | Required IAM action(s) | Upstream request | Success response |
|---|---|---|---|---|---|---|
| C-S3-001 | ListBuckets | `GET /`; `X` | Empty body | `s3:ListAllMyBuckets` on `*` | Not forwarded; control-plane list | R1 |
| C-S3-002 | CreateBucket | `PUT /{bucket}`; `X` | Empty body or bounded `CreateBucketConfiguration` XML | `s3:CreateBucket` on bucket | Not forwarded; control-plane create | R2 |
| C-S3-003 | HeadBucket | `HEAD /{bucket}`; `X` | Empty body | `s3:ListBucket` on bucket | Real bucket root; never apply object prefix | R3 |
| C-S3-004 | ListObjects V1 | `GET /{bucket}`; `prefix`, `delimiter`, `marker`, `max-keys`, `encoding-type`, optional `x-id=ListObjects` | Empty body | `s3:ListBucket` on bucket | Real bucket root; prefix `prefix`/`marker` values | R5 |
| C-S3-005 | ListObjects V2 | `GET /{bucket}`; required `list-type=2`, plus `prefix`, `delimiter`, `continuation-token`, `fetch-owner`, `max-keys`, `encoding-type`, `start-after`, optional `x-id=ListObjectsV2` | Empty body | `s3:ListBucket` on bucket | Real bucket root; prefix key-bearing values | R5 |
| C-S3-006 | ListMultipartUploads | `GET /{bucket}`; required `uploads`, plus `delimiter`, `encoding-type`, `key-marker`, `max-uploads`, `prefix`, `upload-id-marker`, optional `x-id=ListMultipartUploads` | Empty body | `s3:ListBucketMultipartUploads` on bucket | Real bucket root; prefix key-bearing values | R6 |
| C-S3-007 | GetObject | `GET /{bucket}/{key}`; response override keys, `partNumber`, optional `x-id=GetObject` | Range/conditional headers; empty body | `s3:GetObject` on object | Prefix object key | R4 |
| C-S3-008 | HeadObject | `HEAD /{bucket}/{key}`; `partNumber`, optional `x-id=HeadObject` | Conditional headers; empty body | `s3:GetObject` on object | Prefix object key | R3 |
| C-S3-009 | GetObjectVersion | C-S3-007 plus required `versionId` | As C-S3-007 | `s3:GetObjectVersion` on object | Prefix object key; preserve version | R4 |
| C-S3-010 | HeadObjectVersion | C-S3-008 plus required `versionId` | As C-S3-008 | `s3:GetObjectVersion` on object | Prefix object key; preserve version | R3 |
| C-S3-011 | PutObject | `PUT /{bucket}/{key}`; `X` | Object stream; metadata/storage/encryption headers; ACL/grant and tagging headers add their respective IAM checks | `s3:PutObject`, plus `s3:PutObjectAcl` and/or `s3:PutObjectTagging` when used | Prefix object key; stream body | R3 |
| C-S3-012 | PutObjectAcl | `PUT /{bucket}/{key}`; required `acl`, optional `x-id=PutObjectAcl` | ACL XML or ACL/grant headers | `s3:PutObjectAcl` on object | Prefix object key | R3 |
| C-S3-013 | PutObjectTagging | `PUT /{bucket}/{key}`; required `tagging`, optional `x-id=PutObjectTagging` | Tagging XML | `s3:PutObjectTagging` on object | Prefix object key | R3 |
| C-S3-014 | CopyObject | `PUT /{bucket}/{key}`; `X` | Empty body; signed `x-amz-copy-source` in the same virtual bucket; optional ACL/grant and tagging headers | Destination `s3:PutObject`; source `s3:GetObject` or `s3:GetObjectVersion`; optional ACL/tagging actions | Prefix destination and source keys; replace source bucket | R10 |
| C-S3-015 | DeleteObject | `DELETE /{bucket}/{key}`; `X` | Empty body | `s3:DeleteObject` on object | Prefix object key | R3 |
| C-S3-016 | DeleteObjectVersion | C-S3-015 plus required `versionId` | Empty body | `s3:DeleteObjectVersion` on object | Prefix object key; preserve version | R3 |
| C-S3-017 | CreateMultipartUpload | `POST /{bucket}/{key}`; required `uploads`, optional `x-id=CreateMultipartUpload` | Empty body; metadata/storage/encryption headers; ACL/grant and tagging headers add their respective IAM checks | `s3:PutObject`, plus optional ACL/tagging actions | Prefix object key | R7 |
| C-S3-018 | UploadPart | `PUT /{bucket}/{key}`; exactly `partNumber` + `uploadId`, optional `x-id=UploadPart` | Part stream | `s3:PutObject` on object | Prefix object key; stream part | R3 |
| C-S3-019 | ListParts | `GET /{bucket}/{key}`; required `uploadId`, optional `max-parts`, `part-number-marker`, `x-id=ListParts` | Empty body | `s3:ListMultipartUploadParts` on object | Prefix object key | R8 |
| C-S3-020 | CompleteMultipartUpload | `POST /{bucket}/{key}`; required `uploadId`, optional `x-id=CompleteMultipartUpload` | Completed-parts XML, bounded to 1 MiB | `s3:PutObject` on object | Prefix object key | R9 |
| C-S3-021 | AbortMultipartUpload | `DELETE /{bucket}/{key}`; required `uploadId`, optional `x-id=AbortMultipartUpload` | Empty body | `s3:AbortMultipartUpload` on object | Prefix object key | R3 |

“Response override keys” are `response-cache-control`,
`response-content-disposition`, `response-content-encoding`,
`response-content-language`, `response-content-type`, and `response-expires`.

The response profiles are part of the same acceptance boundary:

| Profile | Required behavior |
|---|---|
| R1 | Synthesize ListBuckets XML containing virtual bucket names only. |
| R2 | Synthesize CreateBucket XML and `Location` from the virtual bucket. |
| R3 | Forward only safe status/headers; there is no namespace-bearing success body. |
| R4 | Stream object bytes without buffering; forward only safe object metadata headers. |
| R5 | Stream-transform ListObjects XML, removing the configured prefix from every key/marker/prefix and replacing the bucket name. |
| R6 | Transform ListMultipartUploads XML, including bucket, prefix, key markers, upload keys, and common prefixes. |
| R7 | Transform CreateMultipartUpload bucket/key fields. |
| R8 | Transform ListParts bucket/key and marker fields. |
| R9 | Transform CompleteMultipartUpload bucket/key/location fields. |
| R10 | Transform any namespace-bearing CopyObject success fields. |

For every target profile, non-success XML, redirects, and headers must follow
one global rule: configured real endpoint, bucket, region routing data, access
keys, and path prefix must never be client-visible through proxy-owned S3
metadata. Namespace-bearing bounded control XML is validated and transformed
before response headers commit. Large list XML is root-preflighted and
stream-transformed: a malformed tail can end an already-started 2xx response,
but a namespace-bearing scalar is accumulated and validated before that scalar
is emitted. Object bytes and user-controlled object metadata remain deliberately
byte-transparent and are not content-redacted merely because they contain a
configured string. Hop-by-hop headers, `Connection`-nominated headers, unsafe
trailers, routing-owned backend metadata, and stale representation validators
are removed. Origin redirects are translated to a controlled 502 rather than
followed or exposed; 304 remains an empty response with safe headers.

Backend Owner and Initiator account identities in R5/R6/R8 are replaced with a
stable virtual bucket-scoped identity: both `ID` and `DisplayName` equal the
virtual bucket name. With `fetch-owner=true`, each listed object must carry an
Owner for the proxy to replace. Multipart upload, continuation, and version IDs
are authenticated opaque `vb1` routing tokens; raw origin IDs and cross-mapping
replay fail before origin access. The token domain is bound to the normalized
endpoint/bucket/prefix as well as the control-plane key, so endpoint retargeting
fails closed even before the required key rotation. CompleteMultipartUpload
`Location` is a safe relative URI: `/{bucket}/{escaped-key}` for path-style
requests and `/{escaped-key}` for virtual-hosted requests. The entire logical
key is AWS percent-encoded, including `/`, so a leading-slash key cannot create
a `//host` network-path reference. Deployments that require an
absolute public Location need a future trusted public-base configuration; the
proxy never trusts arbitrary forwarded host/scheme headers for this purpose.

A mapping's path prefix is applied only to object
keys and key-bearing list/multipart fields; bucket-level requests stay at the
real bucket root. Two virtual buckets sharing one backend have disjoint request
namespaces and cannot use one another's routing tokens. Request-echo fields in
list responses must exactly match the rewritten request (including documented
numeric defaults), while result keys/next markers need only remain inside the
configured prefix.

## IAM

Credentials carry a required AWS IAM JSON identity policy. Each proxied
request is evaluated against that policy before forwarding to the real bucket.
Unmatched requests default to implicit deny and a valid explicit `Deny`
overrides `Allow`. The parser rejects malformed JSON/policy structure, unknown
policy elements and condition keys, operator/key type mismatches, and malformed
bool/null/numeric/date operands before a policy can be installed.

The supported surface is the S3 data-plane core that vbuckets can enforce from
the incoming request:

- Bucket resources use `arn:aws:s3:::bucket`; object resources use
  `arn:aws:s3:::bucket/key`.
- Supported policy elements: `Version`, `Statement`, `Sid`, `Effect`,
  `Action`/`NotAction`, `Resource`/`NotResource`, and conditions for string,
  bool, null, numeric, and date comparisons.
- CreateBucket policies may use `s3:LocationConstraint` when the request body
  includes a location constraint.
- The mapping between S3 actions and exact operations is defined by the matrix
  above. Requests outside that grammar fail before virtual bucket lookup, IAM
  evaluation, or proxying.
- CopyObject is supported only within the same virtual bucket. Cross-bucket,
  cross-vbucket, ARN/access-point/absolute URL, and multipart copy requests are
  rejected as unsupported before proxying.
- Unsupported identity-policy features such as `Principal`, policy variables,
  resource policies, session policies, object-tag condition keys, and KMS
  enforcement are rejected or denied.

One effective policy belongs to each virtual access key. The same key can have
different permissions on different virtual buckets, and multiple keys can share
one virtual bucket with different permissions. Bucket inventory and storage
mapping remain control-plane responsibilities. `ListAllMyBuckets` authorizes the
listing operation; its results come from the control plane's per-key inventory,
not from guessing which bucket names might match arbitrary IAM statements.

See the [per-key provisioning guide and executable policy examples](examples/iam/README.md).
`TestPerKeyIAMConformance` exercises both example policies through the real
HTTP/gRPC/watch/cache path, including warmed-cache updates and origin-call
assertions for denied requests. It runs in the short and race suites.

## Control plane

vbuckets connects to a user-provided gRPC control plane service to resolve credentials, bucket mappings, and base hosts. The proto definition is in `api/v1/controlplane.proto`.

You implement the `ControlPlane` service:

```protobuf
service ControlPlane {
  rpc LookupCredentials(LookupCredentialsRequest) returns (LookupCredentialsResponse);
  rpc LookupVBucket(LookupVBucketRequest) returns (LookupVBucketResponse);
  rpc CreateVBucket(CreateVBucketRequest) returns (CreateVBucketResponse);
  rpc ListVBuckets(ListVBucketsRequest) returns (ListVBucketsResponse);
  rpc WatchState(WatchStateRequest) returns (stream WatchEvent);
}
```

Every unary request carries `minimum_revision`, and every response carries the
revision at which it was evaluated. Credential and vbucket lookup responses are
explicit unions: `found=true` requires the complete positive payload and a
positive `ttl`; `found=false` forbids positive fields and requires a positive
`negative_ttl`. Service failures are never converted into cached negatives.
`CreateVBucket` returns only a committed revision strictly greater than the
request minimum; routing is loaded later through `LookupVBucket` after the watch
catches up.

The control plane owns real namespace allocation. Distinct virtual buckets that
share a real endpoint and real bucket MUST use normalized, pairwise
non-overlapping path prefixes; an empty prefix reserves that real bucket
exclusively. Multiple access keys for the same virtual bucket share that bucket's
namespace and routing-token key while keeping independent IAM policies. Each mapping
also carries a required persisted 32-byte random `routing_token_key`. Replicas
must return the same key across lookups, restarts, and upstream credential
rotation while the real endpoint/bucket/prefix namespace is unchanged. The
control plane MUST generate a new key whenever any of those namespace fields
changes; old continuation/upload/version IDs then fail authentication, so a
planned change may need a drain window. Never derive this key from upstream
credentials or fall back when it is absent.

Roll out control-plane storage and population of `routing_token_key` for lookup
responses—and verify replica agreement—before upgrading proxies. Missing or
malformed keys fail closed. Mapping validation also requires
an HTTP(S) endpoint without credentials/path/query/fragment, an S3-valid real
bucket, bounded credentials/region, and a safe normalized prefix. IP-literal
origins require path-style addressing. Virtual-hosted HTTPS mappings with dotted
real bucket names or custom endpoints remain the deployer's DNS/certificate
responsibility.

### Revisioned watch and freshness contract

`WatchState` begins with either a complete base-domain snapshot or a contiguous
replay from the requested `(after_revision, resume_cursor)`. The control plane
then sends a synchronization barrier for the exact accepted pair before live
events. Every persisted revision has one canonical opaque cursor. Live
credential and vbucket events contain only cache keys and invalidation/removal
intent—never secrets, policies, backend credentials, or mappings. The proxy
clears those bounded caches on snapshots and reloads entries through revisioned
unary calls. Base-domain snapshots are staged privately and swapped atomically
at their barrier.

The enforced synchronization contract is:

- Revisions are monotonic. Neither an older unary lookup nor a reordered event
  may replace or be returned after a newer revision has been observed.
- The proxy is not ready at startup or reconnect until it observes an explicit
  synchronization barrier covering its cache state.
- A missing revision, invalid resume cursor, disconnect, or stream failure
  makes the proxy unsynchronized immediately. Readiness fails and authorization
  and routing decisions fail closed until a new barrier is established.
- Cache TTL is a memory/load policy, not a revocation guarantee. After the proxy
  detects an event or stream failure it fails new authorization/routing
  decisions closed until resynchronized. When frames stop, the 10-second watch
  silence timeout bounds detection for *new* resolver decisions. Requests whose
  authorization already completed are not cancelled; because streaming HTTP
  read/write timeouts default to zero, their lifetime is not yet a hard-bounded
  revocation interval. There is no end-to-end hard revocation bound for an
  already-authorized transfer.
- Negative lookup results are revisioned and cached separately from service
  failures. Unavailable/internal responses are never converted into negatives.

A request captures the ready global revision and epoch before resolving its
credentials. After signature verification, bounded control-body parsing, mapping
resolution, and IAM evaluation, it validates that same pair immediately before
dispatch. This final check completes authorization for origin operations,
CreateBucket, and ListBuckets. A change during resolution returns retryable 503;
there is no automatic request replay. Reconnects retire the epoch even when the
revision is unchanged. Changes observed after that boundary do not cancel the
request or undo a confirmed CreateBucket success.

A unary response ahead of the watch records the highest required revision and
makes the proxy temporarily unready while the existing healthy stream catches
up. The current lookup receives 503; the future payload is not cached. Even a
malformed future payload retains its revision evidence. Exact global revision
checks remain conservative: unrelated concurrent updates can also cause 503s,
and sustained churn may exhaust a cold lookup's single retry. Per-key validity
tracking is deferred until workload evidence justifies its complexity.

The watch must emit heartbeats more frequently than the 10-second silence
timeout. Snapshot/replay must reach its synchronization barrier, and live
post-create or future-unary catch-up must reach its required revision, within
the separate 30-second synchronization timeout; traffic cannot extend that
absolute bound. Unary RPCs have a 2-second proxy-owned deadline. Reconnects use
jittered exponential backoff from 250 ms to 30 seconds. These are `ClientOptions`
defaults; the binary does not expose additional environment settings for them.

Resolver not-found/permission results remain 403. Outages, synchronization
changes, and deadlines return 503 `ServiceUnavailable`; miss admission rejection
returns 503 `SlowDown`. Malformed control-plane data returns sanitized 502
`InternalError`. Service errors are never negatively cached.

Health endpoints use the separate administrative listener at `ADMIN_ADDRESS`
(default `127.0.0.1:8081`); point deployment probes there. `/hc` is process
liveness. `/ready` returns 200 only in `ready` and otherwise
503 with one atomic JSON snapshot containing state, revision, cursor presence,
`barrier_required`, required catch-up revision, last gap/disconnect reason,
transition time, cache counts, last RPC status/latency, watch reconnects/gaps, cache
hits/misses/negatives/evictions/coalescing, and separate rejected credential and
vbucket misses. The S3 listener reserves no administrative paths: virtual-hosted
objects named `hc` and `ready` are ordinary signed S3 requests. Both listeners
shut down on SIGINT/SIGTERM with one shared 30-second drain deadline.

The supplied binary serves ordinary HTTP and has no inbound gRPC/h2c upgrade
path or native TLS mode. `aws:SecureTransport` reflects the proxy's actual
`r.TLS` connection state; it is false behind a TLS-terminating proxy forwarding
plain HTTP. Forwarded transport headers remain unsupported and cannot assert
that condition. Control-plane TLS settings below protect the outbound gRPC
connection only.

Object bodies retain bounded streaming copies. Origin read failures or late
list-XML validation failures abort the downstream HTTP/1.1 connection or HTTP/2
stream, so a truncated response cannot become a successful clean EOF. Failures
detected before response headers commit still return sanitized 502 errors.

### Pre-release control-plane migration

This is an intentional breaking change to the pre-release v1 API; it is not
rolling-compatible. Use either a coordinated maintenance cutover or bring up a
parallel control-plane endpoint with compatible new proxies, switch traffic,
and only then retire the legacy deployment. Never connect a legacy proxy to the
new service or a new proxy to the legacy service. A separately versioned service
would be required for an ordinary mixed-version rolling migration. Remove
`LookupBaseHost` and `ListenForDeltas`; add
`WatchState`, a durable monotonic revision/cursor log, exact snapshot/replay
barriers, and heartbeats. Add minimum/revision and found/positive-or-negative
TTL fields to unary DTOs. Make `CreateVBucket` revision-only and retain its
backend mapping in control-plane storage for later lookup. Do not mix old and
new generated clients or servers: protobuf field numbers that formerly carried
sensitive pushed payloads are reserved to prevent accidental reuse.

### Caching

Credential and vbucket lookup results use bounded O(1) LRU/TTL caches with
separate positive and negative TTLs. Base domains use a bounded watch-owned set
with no independent expiry while synchronized. Same-key unary misses are
coalesced, callers can cancel independently, and credential/vbucket novel-key
misses have separate token-bucket and in-flight admission bounds (defaults:
100 requests/second, burst 100, 32 in flight for each type).

Production control-plane lookup/create/delta insertion validates and
defensively clones mappings; the proxy revalidates values returned through the
public `Resolver` interface as a fail-closed adapter boundary. The active mapping
validator, IAM schema, and token codec remain their single implementations;
there is no parallel domain model. Custom resolvers must implement
`BeginResolution` and `ValidateResolution` against their ready revision/epoch
state and return the shared resolver error categories for correct HTTP retry
semantics.

## Development toolchain

The supported compiler is Go 1.26.0, as declared by `go.mod`. Protobuf checks
use Buf v1.72.0 and exact `protoc-gen-go` v1.36.11 revision 1 /
`protoc-gen-go-grpc` v1.6.1 revision 1 remote plugins; `make` invokes the pinned
Buf module with `go run`, so a different globally installed Buf cannot change
results.

- `make generate` refreshes generated Go sources in `api/v1`.
- `make proto-check` lints, generates into an isolated directory, and fails on
  generated-code drift or the wrong output path.
- `make proto-breaking` compares the API with `main` (override with
  `PROTO_BASELINE=<branch>`).
- `make check` runs protobuf lint/drift/breaking gates and the full Go suite.
  The pre-release migration above intentionally fails the breaking check against
  legacy main; review that migration explicitly rather than treating the check
  as passing.
- See [PERFORMANCE.md](./PERFORMANCE.md) for measured main/branch deltas and scope.

### Configuration

The binary loads supported settings once and validates them before starting any
listener. Invalid duration/integer values, nonpositive capacities or mandatory
timeouts, invalid listen addresses, contradictory TLS options, and unreadable
TLS material stop startup. Only HTTP read/write timeouts may be zero to leave
stream durations uncapped. There is no runtime environment reload.

| Variable | Default | Description |
|---|---|---|
| `CONTROL_PLANE_URL` | (required) | gRPC address of the control plane (e.g. `localhost:9090`) |
| `HTTP_ADDRESS` | `:8080` | Listen address for the HTTP/S3 proxy |
| `ADMIN_ADDRESS` | `127.0.0.1:8081` | Separate health/readiness listener; use a reachable bind address for remote deployment probes |
| `SIGV4_MAX_CLOCK_SKEW` | `15m` | Max allowed absolute skew for `X-Amz-Date` before returning `RequestTimeTooSkewed` |
| `CACHE_MAX_CREDENTIALS` | `10000` | Max entries in the credentials cache |
| `CACHE_MAX_BASE_HOSTS` | `10000` | Max entries in the watch-owned base-domain registry |
| `CACHE_MAX_VBUCKETS` | `10000` | Max entries in the vbucket cache |

### Control plane security

| Variable | Default | Description |
|---|---|---|
| `CONTROL_PLANE_SECURITY_MODE` | `insecure` | Transport mode: `insecure`, `tls`, or `mtls` |
| `CONTROL_PLANE_TLS_CA_FILE` | (unset) | Optional CA bundle for control plane TLS |
| `CONTROL_PLANE_TLS_SERVER_NAME` | (unset) | Optional TLS server name override |
| `CONTROL_PLANE_TLS_CERT_FILE` | (unset) | Client cert file for `mtls` |
| `CONTROL_PLANE_TLS_KEY_FILE` | (unset) | Client key file for `mtls` |
| `CONTROL_PLANE_AUTH_BEARER_TOKEN` | (unset) | Optional bearer token sent as gRPC `authorization` metadata |

### HTTP and upstream timeouts

| Variable | Default | Description |
|---|---|---|
| `HTTP_READ_HEADER_TIMEOUT` | `10s` | Max time to read incoming request headers |
| `HTTP_IDLE_TIMEOUT` | `2m` | Max keep-alive idle time |
| `HTTP_READ_TIMEOUT` | `0s` | Total request read timeout (`0s` disables hard cap for streaming) |
| `HTTP_WRITE_TIMEOUT` | `0s` | Total response write timeout (`0s` disables hard cap for streaming) |
| `UPSTREAM_DIAL_TIMEOUT` | `30s` | Upstream TCP dial timeout |
| `UPSTREAM_TLS_HANDSHAKE_TIMEOUT` | `10s` | Upstream TLS handshake timeout |
| `UPSTREAM_RESPONSE_HEADER_TIMEOUT` | `30s` | Upstream response header timeout |
| `UPSTREAM_EXPECT_CONTINUE_TIMEOUT` | `1s` | Upstream `100-continue` wait timeout |
| `UPSTREAM_IDLE_CONN_TIMEOUT` | `90s` | Upstream idle connection timeout |
| `UPSTREAM_MAX_IDLE_CONNS` | `100` | Max idle upstream connections across all hosts |
| `UPSTREAM_MAX_IDLE_CONNS_PER_HOST` | `100` | Max idle upstream connections per host |
