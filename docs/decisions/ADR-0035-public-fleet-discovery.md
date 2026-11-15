# ADR-0035: Anonymous public fleet discovery

Status: Accepted
Date: 2026-11-09
Governing issue: #62

## Decision and scope

Add one concrete public repository/manifest producer for the accepted G06 fleet route. Its named next consumers are the G03 candidate owner, G06 governance/pilot processing and G07 inventory/executor. This source prerequisite does not expose a CLI command or complete inventory projection, governed draft creation or issue acceptance. The source decision is accepted within the coordinator's reviewed G01–G08 direction; implementation review and runtime qualification remain separate.

`discoverPublicManifests` uses Node's trusted built-in fetch with fixed anonymous HTTPS GET requests to `api.github.com`, API version `2026-03-10`, omitted credentials and redirects rejected. There is no endpoint, transport-callback, token or proxy parameter. The process/runtime remains trusted; this does not attest a caller-modified global dispatcher or TLS implementation. No signer, model, provider credential or target instruction is selected.

Public repository identities and organization ownership must match every read. Complete bounded organization pagination follows only validated consecutive page numbers, reconstructing the fixed organization URL rather than following a caller/server-selected endpoint. Duplicate identities, malformed links, truncated trees, unexpected HTTP failures and rate limits stop with an incomplete result. An unexpected 404 is not evidence that a manifest is absent.

For each enabled repository, read the exact default ref, raw commit metadata, complete nonrecursive root tree and selected `project.bootstrap.yaml` blob. Only absence in that complete root tree is unmanaged. Both regular file modes are supported; symlinks/submodules are unsupported. Verify declared size, canonical Base64, Git blob SHA-1 and an additional SHA-256 of the actual bytes. These are source-bound public API observations, not independent raw-commit signature verification.

Decode bounded UTF-8 and strict YAML without aliases or custom tags. Bound the converted graph before passing it to the existing full, pure `normalizeManifest`; do not use filesystem-based `loadManifest` or resolve a policy bundle. Unknown settings, invalid structure, or project identity/visibility/default-branch mismatch yield a constant unsupported outcome. The producer never executes declared commands or reads declared host paths.

Repeat organization enumeration and recapture repository/default-head identities before registering a complete result. This detects observed membership, identity and head changes. Sequential API reads are not an atomic global snapshot, and a later change remains possible. Later execution must perform its own fresh audits.

## Bounds, output and ownership

The fixed profile permits at most ten pages, 500 repositories and 5,000 requests, with 15 seconds per request and 120 seconds for the operation using a monotonic clock. Stream limits are 2 MiB per response and 64 MiB consumed across the operation; a manifest is at most 256 KiB. Root trees have at most 10,000 entries, and converted YAML has at most 16,384 nodes and depth 32. Check consumed bytes before copying each chunk. These logical/input limits do not certify every fetch, parser or native allocation.

Reports expose only allowlisted public repository/object identities, fixed outcomes, flags, counters and sanitized failure codes. Raw manifests are retained privately only for canonical managed records. `readDiscoveredManifest` requires the actual complete result and its actual managed record; copied JSON/objects and incomplete prefixes cannot recover body data. This private identity is a data binding, not authority to sign, validate a pilot, apply changes or publish.

Archived/forked repositories remain visible as flags; they are not automatically eligible. Disabled repositories remain explicitly unsupported. A complete discovery means the bounded observations finished successfully, including unsupported/unmanaged entries. It does not mean every repository can execute an upgrade.

## Validation and remaining integration

Meaningful fixtures exercise the actual default fetch route and fixed arguments, both documented pagination URL forms, immutable object/size/hash checks, full canonical normalization without host reads, raw-body non-disclosure, copied/incomplete result rejection, unsupported manifests, streaming/aggregate limits, cancellation, monotonic deadlines and moving identities. Fixture responses are fabricated; no live fleet inventory, authentication or native profile is qualified by these tests.

Genuine controlled policy-bundle loading, class/pin/exception reporting, managed-file drift projection, authenticated pilot evidence and the full guarded executor remain necessary. No schema, dependencies, managed files, manifest, legal output, seven existing fleet helpers or repository settings change here. New state/apply is unnecessary for these unmanaged source files; built doctor and a real unchanged repository plan verify that boundary.

## References

- [Organization repositories](https://docs.github.com/en/rest/repos/repos#list-organization-repositories)
- [REST pagination](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api)
- [Git references](https://docs.github.com/en/rest/git/refs#get-a-reference)
- [Git commits](https://docs.github.com/en/rest/git/commits#get-a-commit-object)
- [Git trees](https://docs.github.com/en/rest/git/trees#get-a-tree)
- [Git blobs](https://docs.github.com/en/rest/git/blobs#get-a-blob)
