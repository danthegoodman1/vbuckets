# vbuckets

An S3-compatible reverse proxy that maps virtual buckets and credentials to real S3 backends. Designed for whitelabeling -- give tenants their own bucket names, access keys, and IAM policies without exposing your underlying storage.

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

Clients connect with virtual credentials and virtual bucket names. vbuckets verifies the SigV4 signature, resolves the virtual bucket to a real backend (bucket, endpoint, region, credentials, optional path prefix), checks IAM permissions, then re-signs and proxies the request. Supports both virtual-hosted (`bucket.s3.example.com/key`) and path-style (`s3.example.com/bucket/key`) addressing in both directions.

## Lookup functions

The auth middleware is split into two phases with three distinct lookups, each independently cacheable:

| Lookup | Input | Returns |
|---|---|---|
| `lookupCredentials` | access key ID | secret key, IAM policy |
| `lookupBaseHost` | request hostname | base domain (if registered) |
| `lookupVBucket` | access key ID + bucket name | real endpoint, bucket, region, path prefix, addressing style |

`lookupBaseHost` determines whether an incoming request is virtual-hosted style (`bucket.s3.example.com`) or path style (`s3.example.com/bucket`) by checking if the hostname is (or is a subdomain of) a registered base domain. The set of base domains changes extremely rarely, so this is aggressively cacheable.

**Phase 1 (authentication)** runs `lookupCredentials` and verifies the SigV4 signature before any bucket resolution happens. **Phase 2 (authorization)** resolves the bucket via `lookupBaseHost` + `lookupVBucket`, then checks IAM permissions. This separation means credential caches don't need to be invalidated when bucket mappings change and vice versa.

## IAM

Credentials use the same IAM as AWS.

Each proxied request is checked against the virtual IAM credentials before forwarding to the real bucket.


## Control plane

All three lookup functions currently read from environment variables (single-tenant). In production these will call out to a control plane service that manages credentials, bucket mappings, and IAM policies.

The control plane API is not yet implemented. It will likely be gRPC (the server already multiplexes gRPC alongside HTTP on the same port via h2c) but may end up as an HTTP JSON API instead. The interface is intentionally narrow -- vbuckets only needs the three lookups above -- so swapping transports is trivial.

The benefit of gRPC is an Envoy xDS-like behavior where you can push cache invalidations very quickly (e.g. delete keys, change permissions)
