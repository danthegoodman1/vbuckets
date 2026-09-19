# Provisioning IAM per virtual access key

The proxy already evaluates one compiled identity policy per access key on every
request. Provision that policy through the existing `LookupCredentials` response;
no new authorization RPC or bucket-policy layer is required.

This repository implements the proxy/client. Your control plane owns durable
credential storage, key issuance, bucket membership, and policy administration.
The executable example in `e2e/iam_conformance_test.go` uses the real proxy and
gRPC client with a small in-memory test server and a permissive HTTP origin. Its
single-watch event channel is a test fixture, not a production persistence or
broadcast implementation.

## Example grants

The conformance test loads these JSON files directly, so the examples are tested
against the same policy compiler and enforcement path used in production.

| Example key | Policy | Bucket inventory | Permissions |
| --- | --- | --- | --- |
| `reader` | [scoped-reader.json](scoped-reader.json) | `photos`, `archive` | Read `photos/public/*`, except explicit denial of `photos/public/private/*`; list with a `public/` prefix; write only `archive/inbox/*`. |
| `writer` | [writer.json](writer.json) | `photos` | Write `photos/*`; read only `photos/copy-source/*`, allowing copy from that prefix. |

Both keys grant `s3:ListAllMyBuckets` on `*`, but each sees only its control-plane
inventory. The resource names in both policies are **virtual** bucket/object
names, never the real bucket or storage prefix. Keys sharing `photos` receive
the same physical namespace and stable routing-token key. Their IAM policies and
credentials remain separate.

`ListBucket` is a separate permission from `GetObject`. A denial of reads under
`public/private/` does not remove those names from an otherwise authorized
listing of `public/`. The `s3:prefix` condition restricts the requested listing
prefix; the proxy does not filter individual results using object permissions.

`PutObject` permits multipart initiation, part upload, and completion within the
allowed resource scope. ListParts and AbortMultipartUpload need their separate
IAM actions; possession of an upload token grants no permission. Copy needs
both source read and destination write. ACL/tagging headers require their extra
permissions. The example writer does not receive these additional permissions.

## Control-plane storage and update contract

Keep one effective policy JSON document alongside each virtual access key's
secret and enabled/disabled state. Keep bucket membership separate from that
policy, and keep physical namespace allocation per virtual bucket. A key may
have a mapping but still be denied an operation by its policy; a policy does not
create a mapping or membership by itself.

For provisioning or updating a key:

1. Validate the candidate policy using the same supported schema. Go control
   planes can call `http_server.ParseS3IAMPolicyJSON`. Reject malformed or
   unsupported policies before replacing the stored policy. An explicit deny-all
   policy is valid; a missing/empty policy is not.
2. In one durable transaction, store the credential/policy change, advance the
   global revision, and append its watch event (or a transactional outbox entry).
   A restart must not lose the invalidation after committing the policy.
3. Publish `CredentialsDelta{access_key_id: key}` at that committed revision with
   its canonical cursor. This invalidates a cached credential or negative lookup;
   do not push the secret or policy in the event. Every connected proxy must
   receive the event in global order, with replay/snapshot recovery as documented
   in the main README.
4. `LookupCredentials` must return the secret and policy from one consistent
   snapshot, with that snapshot's global revision, at least `minimum_revision`.
   `found=true` requires a policy, secret, and positive TTL. Unknown/disabled keys
   return `found=false` and a positive negative TTL; service failures are errors.
5. For removal/disable, emit a credential delta with `remove=true` and a positive
   `negative_ttl`. Re-enabling uses an ordinary invalidation so a hot negative
   cache entry cannot hide the newly enabled key.
6. Membership/mapping changes also require the corresponding `VBucketDelta`.
   Treat policy changes as credential changes even when the secret is unchanged.
   Never revoke a key by changing only its `ListVBuckets` inventory while leaving
   `LookupVBucket` access or stale mappings active.

After observing the invalidation, the proxy cannot complete a new authorization
with the retired policy. Authorization already completed before that observation
retains the documented streaming exemption. Persisting an update is not an
acknowledgment that every proxy has observed it; use the existing watch readiness
and detection contract rather than promising instantaneous fleet revocation.

## Verification

```sh
go test ./e2e -short -run '^TestPerKeyIAMConformance$' -count=1
go test -race ./e2e -short -run '^TestPerKeyIAMConformance$' -count=1
```

The test covers two keys sharing one bucket; one key with different permissions
on two buckets; explicit deny and prefix restrictions; distinct per-key bucket
inventories; copy and multipart permission checks; and policy replacement through
a live watch after warming both credential caches. Every denied request asserts
zero origin calls. The origin performs no key-level authorization, preventing an
origin denial from masquerading as successful proxy enforcement. Invalid policy
updates preserve the previous policy and revision; valid updates reload only
the changed key and can restore access without rotating its secret.
