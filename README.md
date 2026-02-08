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

Clients connect with virtual credentials and virtual bucket names. vbuckets verifies the SigV4 signature (including request-time skew checks), resolves the virtual bucket to a real backend (bucket, endpoint, region, credentials, optional path prefix), checks IAM permissions, then re-signs and proxies the request. Supports both virtual-hosted (`bucket.s3.example.com/key`) and path-style (`s3.example.com/bucket/key`) addressing in both directions.

## Lookup functions

The auth middleware is split into two phases with three distinct lookups, each independently cacheable:

| Lookup | Input | Returns |
|---|---|---|
| `LookupCredentials` | access key ID | secret key, IAM policy, TTL |
| `LookupBaseHost` | request hostname | base domain (if registered), TTL |
| `LookupVBucket` | access key ID + bucket name | real endpoint, bucket, region, path prefix, addressing style, TTL |

`LookupBaseHost` determines whether an incoming request is virtual-hosted style (`bucket.s3.example.com`) or path style (`s3.example.com/bucket`) by checking if the hostname is (or is a subdomain of) a registered base domain. The set of base domains changes extremely rarely, so this is aggressively cacheable.

**Phase 1 (authentication)** runs `LookupCredentials` and verifies the SigV4 signature before any bucket resolution happens. **Phase 2 (authorization)** resolves the bucket via `LookupBaseHost` + `LookupVBucket`, then checks IAM permissions. This separation means credential caches don't need to be invalidated when bucket mappings change and vice versa.

## Path prefix rewriting

When a vbucket mapping includes a path prefix, all object keys are transparently scoped under that prefix in the real bucket. For single-object operations (GET, PUT, DELETE, etc.) the prefix is prepended to the key in the URL path. For ListObjects V1/V2 the proxy rewrites the `prefix`, `start-after`, and `marker` query parameters on the way out, and strips the prefix from keys, common prefixes, and other echoed fields in the XML response on the way back.

## IAM

> [!IMPORTANT]
> This is not yet implemented.
> Currently, all vcredentials keys have full access to their vbuckets

Credentials use the same IAM as AWS.

Each proxied request is checked against the virtual IAM credentials before forwarding to the real bucket.

## Control plane

vbuckets connects to a user-provided gRPC control plane service to resolve credentials, bucket mappings, and base hosts. The proto definition is in `api/v1/controlplane.proto`.

You implement the `ControlPlane` service:

```protobuf
service ControlPlane {
  rpc LookupCredentials(LookupCredentialsRequest) returns (LookupCredentialsResponse);
  rpc LookupBaseHost(LookupBaseHostRequest) returns (LookupBaseHostResponse);
  rpc LookupVBucket(LookupVBucketRequest) returns (LookupVBucketResponse);
  rpc ListenForDeltas(ListenForDeltasRequest) returns (stream Delta);
}
```

The three unary RPCs handle on-demand lookups. Each response includes a `ttl` field that controls how long the proxy caches that entry.

### Delta stream

`ListenForDeltas` is a server-streaming RPC that pushes cache updates to the proxy. When credentials are revoked, bucket mappings change, or base hosts are added/removed, the control plane sends a `Delta` message with the full updated value (upsert) or a removal flag. This gives an Envoy xDS-like pattern: long-lived caches with fast, precise invalidation -- no polling, no stale windows.

Each delta also carries a `ttl` so the control plane controls per-entry cache lifetimes even for pushed data.

### Caching

Lookup results and deltas are cached locally, going to the control plane as needed. Three independent caches (credentials, base hosts, vbuckets) each use per-entry TTLs from the control plane. Cache misses trigger the unary gRPC lookup; concurrent requests for the same key are deduplicated automatically to protect the control plane from thundering herds.

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
