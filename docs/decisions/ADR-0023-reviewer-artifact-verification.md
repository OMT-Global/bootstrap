# ADR-0023: Pinned public reviewer artifact verification

Status: Accepted for source and CI preparation only. Derived bundles and hosted verification remain pending.

Date: 2026-11-08

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62). This prerequisite does not complete its native reviewer or fleet publication contract.

## Context

The public native reviewer prototype at `f410d6bdda984778db1e049d51287617f80dbe35` reached archive extraction in [run 42537783405](https://github.com/OMT-Global/bootstrap/actions/runs/42537783405), then failed before image construction or native execution. The discarded process stderr prevents attributing the exact observed failure. Independently, its inputs are incompatible: the official OpenAI release signs legacy bundles and Cosign 3.1.4 rejects a legacy bundle with `--trusted-root`.

The artifact prerequisite extracts the existing public download, hash, archive, notice and Cosign responsibilities. Native sandbox, Docker fixture, authentication, mock provider, helper integration and publication controls remain outside this change.

## Decision

Keep the exact Codex 0.167.0 source `086ccc833bc9cf01024ad2dd6af7dbd421b6bf9a`, complete package, native and bubblewrap hashes, Cosign 3.1.4 binary, workflow identity and GitHub Actions issuer. Retain trusted-root snapshot `c9bda74ad2221f938f7d2e0295ca3aad2da710a8`, SHA-256 `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66` and offline signature verification. Do not replace the root document with raw PEM overrides or ambient TUF: the modern verifier uses its Rekor, CT and CA validity metadata.

Separate public metadata acquisition from ordinary verification. Explicit CI-only `--prepare-metadata` runs pinned Cosign's official `bundle create --artifact FILE --bundle LEGACY --out STANDARD --rekor-url https://rekor.sigstore.dev` under a cleared environment and a fresh private temporary home. This performs a public Rekor lookup; it is not an offline conversion and is never invoked by `stage()`.

Before any derived bundle is emitted, require exact certificate DER, signature, Rekor canonical body bytes, log ID, global index, integrated time and signed-entry-timestamp equality with the SHA-pinned legacy inputs. Require the expected artifact digest and hashedrekord 0.0.1 kind/version. Preserve the complete official standardized bytes, including supplemental inclusion proof and checkpoint, then verify the exact package, native and bubblewrap artifacts with the original offline command. The representation audit performs no custom cryptography; Cosign performs every cryptographic check.

Cosign constructs media type `application/vnd.dev.sigstore.bundle+json;version=0.3`, `verificationMaterial.certificate.rawBytes` and `messageSignature`. Bytes use standard base64, int64 fields use decimal strings, and the original body is not recanonicalized. The proof index is relative to its individual tree; it must not equal the original global log index. The audit permits that distinction and requires the proof/checkpoint structure to remain present.

Preparation emits only bounded public evidence, including exact bundle bytes encoded as base64 plus size and SHA-256, after all equality and offline-verification checks pass. Root captures and reviews those actual bytes before adding immutable bundle files and pins. Missing pins fail closed before acquisition; no synthesized bundle, automatic preparation, live trust fallback, configurable endpoint or native execution is available through the default path.

The initial preparation-only WIP deliberately uses `--prepare-metadata` in the full profile of the existing registered validation entrypoint. After actual derived inputs are captured and pinned, the final manifest and generated entrypoint must use default verification. The existing immutable reusable caller `913b298fab0fb008796011d940ee7362a347659d` and all runner/workflow settings remain unchanged. Fast, smoke and standard profiles perform no new artifact downloads.

The reusable `stage(directory, absolute_deadline=None)` accepts only a fresh, private, empty owned directory. It returns paths and metadata for verified public artifacts, never a native-support, model-review or fleet receipt. It has a hard 15-minute acquisition budget capped by an earlier caller deadline. Its CLI owns a separate 60-second cleanup budget. Subprocess combined output, process groups, downloads, extraction members, paths, types, modes and expanded bytes remain bounded. Only the three fixed public Cosign verification calls emit JSON-escaped stderr and exit status; no runtime or authentication output is involved.

Preserve the complete official package layout and all package notices, including voice resources, plus the pinned Codex, bubblewrap and ripgrep notices. The download SHA check precedes archive parsing. Extraction rejects links/devices, traversal, unsafe modes, duplicate names and file-parent collisions within the existing 2-GiB, 4096-member, depth-32 envelope. The official pinned archive has already been observed to contain 52 members and 540530246 expanded bytes; this source change does not claim a new extraction or verification run.

## Primary sources

- [OpenAI's pinned legacy signing flags](https://github.com/openai/codex/blob/086ccc833bc9cf01024ad2dd6af7dbd421b6bf9a/.github/actions/linux-code-sign/action.yml#L65) and [Cosign's legacy trusted-root rejection](https://github.com/sigstore/cosign/blob/0e48502cf5ef34e2e60bbd3617aa19945712f705/cmd/cosign/cli/verify/verify_blob.go#L172).
- [Official conversion](https://github.com/sigstore/cosign/blob/0e48502cf5ef34e2e60bbd3617aa19945712f705/cmd/cosign/cli/bundle/bundle.go#L69), [v0.3 construction and lookup](https://github.com/sigstore/cosign/blob/0e48502cf5ef34e2e60bbd3617aa19945712f705/cmd/cosign/cli/verify/verify_bundle.go#L54) and [fixed Rekor option](https://github.com/sigstore/cosign/blob/0e48502cf5ef34e2e60bbd3617aa19945712f705/cmd/cosign/cli/options/bundle.go#L30).
- [Definitive Rekor field mapping](https://github.com/sigstore/rekor/blob/v1.5.4/pkg/tle/tle.go#L33), [protojson encoding](https://github.com/protocolbuffers/protobuf-go/blob/v1.36.12/encoding/protojson/encode.go#L311) and [v0.3 certificate representation](https://github.com/sigstore/sigstore-go/blob/v1.3.0/pkg/bundle/bundle.go#L123).
- [Rekor validity](https://github.com/sigstore/sigstore-go/blob/v1.3.0/pkg/tlog/entry.go#L536), [CT validity](https://github.com/sigstore/sigstore-go/blob/v1.3.0/pkg/verify/sct.go#L66) and [CA validity](https://github.com/sigstore/sigstore-go/blob/v1.3.0/pkg/root/certificate_authority.go#L37).

## Validation and limits

Static synthetic regressions exercise representation mismatches, proof retention, missing pins, archive safety, URL restrictions, combined output, process errors and interruption by the absolute acquisition clock. The existing entrypoint tests retain ordering and cheap-profile checks and add the exact preparation command and its failure propagation. The manifest and generated script are backed up and the scoped projection is compared byte-for-byte; all 13 existing plan drift classifications are preserved.

Mac validation does not download or execute the Linux package or Cosign, start Docker, inspect operator authentication, contact a provider or create a model review. Actual public conversion and trusted-root signature verification require the separately reviewed, exact hosted run. Native support, complete autoreview receipts and fleet publication remain unproven. The baseline doctor reports local GitHub authentication as a warning; no authentication change is part of this prerequisite.
