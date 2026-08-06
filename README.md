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

## Lookup functions

The auth middleware is split into two phases with three distinct lookups, each independently cacheable:

| Lookup | Input | Returns |
|---|---|---|
| `LookupCredentials` | access key ID | secret key, IAM policy, TTL |
| `LookupBaseHost` | request hostname | base domain (if registered), TTL |
| `LookupVBucket` | access key ID + bucket name | real endpoint, bucket, region, path prefix, addressing style, TTL |
| `CreateVBucket` | access key ID + bucket name + location constraint | real endpoint, bucket, region, path prefix, addressing style, TTL |
| `ListVBuckets` | access key ID | visible virtual bucket names and creation dates |

`LookupBaseHost` determines whether an incoming request is virtual-hosted style (`bucket.s3.example.com`) or path style (`s3.example.com/bucket`) by checking if the hostname is (or is a subdomain of) a registered base domain. The set of base domains changes extremely rarely, so this is aggressively cacheable.

**Phase 1 (authentication)** runs `LookupCredentials` and verifies the SigV4 signature before any bucket resolution happens. **Phase 2 (authorization)** resolves the request shape and checks IAM permissions. Object and bucket-object operations use `LookupBaseHost` + `LookupVBucket` before proxying. `CreateBucket` uses `CreateVBucket`, and `ListBuckets` uses `ListVBuckets`; neither operation is forwarded to the origin service.

## Target S3 operation and virtualization contract

This matrix is the enforced acceptance contract for the request planner and
the acceptance contract for the remaining Phase 2 namespace transforms. Today,
requests are decoded once into a typed operation plan, and unknown, duplicate,
conflicting, or operation-mismatched query/header shapes fail before virtual
bucket mapping or IAM evaluation. Prefix rewriting is still applied too broadly
to bucket-level requests, only successful ListObjects XML has a namespace-aware response
transform, upstream multipart/error/redirect metadata may pass through, and
hop-by-hop filtering does not yet remove headers named by `Connection`. Until
Phase 2 closes those response and rewrite gaps, deployments must not rely on the
complete no-leak/prefix-isolation properties below.

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
`url`.

The signing headers described above are required on
every row. Ordinary HTTP content, range, and conditional headers are allowed
where their HTTP method uses them, as are signed `x-amz-meta-*` object metadata
headers. ACL/grant, tagging, copy, storage-class, and server-side-encryption
headers affect an operation and are accepted only where called out below.
Session tokens, KMS-specific and object-lock request forms, signed/checksummed
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

The target response profiles are part of the same acceptance boundary:

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
keys, and path prefix must never be client-visible. Phase 2 will validate and
transform namespace-bearing control XML before committing response headers
while keeping unbounded object and list bodies streaming. It must strip
hop-by-hop headers, headers named by `Connection`, unsafe trailers, upstream
endpoint headers, and stale length/checksum metadata after a body transform.

Under the completed contract, a mapping's path prefix is applied only to object
keys and key-bearing list/multipart fields; bucket-level requests stay at the
real bucket root. The Phase 2 gate will prove that two virtual buckets sharing
one backend have disjoint request namespaces and cannot infer each other's
configured identifiers from successes, errors, or redirects.

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

## Control plane

vbuckets connects to a user-provided gRPC control plane service to resolve credentials, bucket mappings, and base hosts. The proto definition is in `api/v1/controlplane.proto`.

You implement the `ControlPlane` service:

```protobuf
service ControlPlane {
  rpc LookupCredentials(LookupCredentialsRequest) returns (LookupCredentialsResponse);
  rpc LookupBaseHost(LookupBaseHostRequest) returns (LookupBaseHostResponse);
  rpc LookupVBucket(LookupVBucketRequest) returns (LookupVBucketResponse);
  rpc CreateVBucket(CreateVBucketRequest) returns (CreateVBucketResponse);
  rpc ListVBuckets(ListVBucketsRequest) returns (ListVBucketsResponse);
  rpc ListenForDeltas(ListenForDeltasRequest) returns (stream Delta);
}
```

The unary RPCs handle on-demand lookups and intercepted create/list operations. Lookup and create responses include a `ttl` field that controls how long the proxy caches that entry.

### Delta stream

`ListenForDeltas` is a server-streaming RPC that pushes cache updates to the proxy. When credentials are revoked, bucket mappings change, or base hosts are added/removed, the control plane sends a `Delta` message with the full updated value (upsert) or a removal flag.

Each delta also carries a `ttl` so the control plane controls per-entry cache lifetimes even for pushed data.

The current pre-release v1 messages do not carry a revision, resume cursor, or
initial synchronization barrier. Its delta stream is therefore best-effort:
it shortens ordinary propagation but cannot claim “no stale windows.” Before
the control-plane API is production-ready, its revisioned synchronization
contract is:

- Revisions are monotonic. Neither an older unary lookup nor a reordered event
  may replace or be returned after a newer revision has been observed.
- The proxy is not ready at startup or reconnect until it observes an explicit
  synchronization barrier covering its cache state.
- A missing revision, invalid resume cursor, disconnect, or stream failure
  makes the proxy unsynchronized immediately. Readiness fails and authorization
  and routing decisions fail closed until a new barrier is established.
- Cache TTL is a memory/load policy, not a revocation guarantee. Maximum
  revocation exposure is measured as stream-failure detection time plus
  control-plane resynchronization time; both components must be observable and
  bounded by deployment configuration.
- Negative lookup results are revisioned and cached separately from service
  failures. Unavailable/internal responses are never converted into negatives.

### Caching

Lookup results and deltas are cached locally, going to the control plane as needed. Three independent caches (credentials, base hosts, vbuckets) each use per-entry TTLs from the control plane. Cache misses trigger the unary gRPC lookup; concurrent requests for the same key are deduplicated automatically to protect the control plane from thundering herds.

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

### Configuration

| Variable | Default | Description |
|---|---|---|
| `CONTROL_PLANE_URL` | (required) | gRPC address of the control plane (e.g. `localhost:9090`) |
| `HTTP_ADDRESS` | `:8080` | Listen address for the HTTP/S3 proxy |
| `SIGV4_MAX_CLOCK_SKEW` | `15m` | Max allowed absolute skew for `X-Amz-Date` before returning `RequestTimeTooSkewed` |
| `CACHE_MAX_CREDENTIALS` | `10000` | Max entries in the credentials cache |
| `CACHE_MAX_BASE_HOSTS` | `10000` | Max entries in the base host cache |
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
