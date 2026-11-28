# node-npm-linux-v1 image provenance

## Debian 13 candidate

[ADR-0066](../decisions/ADR-0066-isolated-release-python-floor.md) proposes moving the Linux/amd64 validation profile to the Debian 13 variant of the same Microsoft Dev Containers Node 24 release. The immutable manifest is pinned in code and both hosted validation pull sites.

| Artifact | Identity |
|---|---|
| Observation tag | `5.2.5-24-trixie` |
| [OCI index](https://mcr.microsoft.com/v2/devcontainers/javascript-node/manifests/5.2.5-24-trixie) | `sha256:2015e2c863cb1e608bc0876860dd063cdb9e3d9a02dca63d1c2fce8fad02d088` |
| [Linux/amd64 manifest](https://mcr.microsoft.com/v2/devcontainers/javascript-node/manifests/sha256:7f53703699da429555e7eebed7047e12823dac65508831413b5485e4566c00a8) | `sha256:7f53703699da429555e7eebed7047e12823dac65508831413b5485e4566c00a8` |
| [Image config](https://mcr.microsoft.com/v2/devcontainers/javascript-node/blobs/sha256:3530e3f4573759355f8261e2c4c65cded6b6d1e621447614720c59a44233aa66) | `sha256:3530e3f4573759355f8261e2c4c65cded6b6d1e621447614720c59a44233aa66` |
| [Referenced attestation manifest](https://mcr.microsoft.com/v2/devcontainers/javascript-node/manifests/sha256:fc9b1a2d17ff20e429902e585359c6090e2d5e3793308de02303d88e9cbcab8d) | `sha256:fc9b1a2d17ff20e429902e585359c6090e2d5e3793308de02303d88e9cbcab8d` |
| [Referenced SLSA statement](https://mcr.microsoft.com/v2/devcontainers/javascript-node/blobs/sha256:48292d8bd4c66d389efb1fb009de6834fa9f4241252ff63c71051b28773c7e58) | `sha256:48292d8bd4c66d389efb1fb009de6834fa9f4241252ff63c71051b28773c7e58` |

The config records creation on 2026-10-28, Linux/amd64, Node 24.22.1, user `root` and entrypoint `docker-entrypoint.sh`. The [publisher's exact variant manifest](https://github.com/devcontainers/images/blob/25ae116762a2dcbca01cf61aadc2c8d1a1421533/src/javascript-node/manifest.json) lists `24-trixie`. The package database read from the final image layers reports `python3` 3.13.5-1, `python3.13` 3.13.5-2+deb13u5, and `jq` 1.7.1-6+deb13u4. [Debian's trixie Python package](https://packages.debian.org/trixie/python3) identifies Python 3.13 as the default.

The SLSA statement names the exact platform manifest as its subject and records incomplete resolved dependencies. Its verified digest establishes byte identity. Independent image-signature verification and a complete build-material chain remain unestablished. Qualify the actual interpreter, existing six-tool set, and confinement in the complete hosted test suite on the exact candidate revision.

## Historical Debian 12 image

ADR-0013 pinned `mcr.microsoft.com/devcontainers/javascript-node@sha256:447fa75fbc7123952284b50229148e933ea756c40718601fa0ec46edd29fd0c6`, Linux/amd64. The historical record below documents the six-tool selection and its evidence boundaries.

### Observed OCI identities

Anonymous registry metadata observed on 2026-11-08 had response-body SHA-256 identities matching the recorded references. No image layers were downloaded or executed during this source/metadata research.

| Artifact | Identity |
|---|---|
| Documented observation tag | `5.2.5-24-bookworm` (runtime uses the digest) |
| [OCI index](https://mcr.microsoft.com/v2/devcontainers/javascript-node/manifests/5.2.5-24-bookworm) | `sha256:1bc82e3350b0da52ca1a1b1b2e7527300bc6fdfd778287e0eed564203d66a68c` |
| [Linux/amd64 manifest](https://mcr.microsoft.com/v2/devcontainers/javascript-node/manifests/sha256:447fa75fbc7123952284b50229148e933ea756c40718601fa0ec46edd29fd0c6) | `sha256:447fa75fbc7123952284b50229148e933ea756c40718601fa0ec46edd29fd0c6` |
| [Image config](https://mcr.microsoft.com/v2/devcontainers/javascript-node/blobs/sha256:c241d217ee58a3e3cc51cd1ac37c5b14151b8a278f2f03b95f35ce0743102522) | `sha256:c241d217ee58a3e3cc51cd1ac37c5b14151b8a278f2f03b95f35ce0743102522` |
| Referenced attestation manifest | `sha256:a8fce51c17404b02b74f1211e4a3759e739dd97eb61e4c64cbabb834a7ec86e7` |
| Referenced SLSA statement | `sha256:91fe1e94dc74b2e303567bc5f8c477b89c326f7e82ead220dcd8ddadfdccacdb` |

The config records creation on 2026-10-28, `amd64`, `linux`, and `NODE_VERSION=24.22.1`. The earlier official Node candidate actually ran 24.22.2. The profile requires Node 24 and will record its actual probe result; the patch difference is intentional and carries no assertion of equivalent security or newer patch coverage.

### Source chain and limits

The [official release commit](https://github.com/devcontainers/images/commit/25ae116762a2dcbca01cf61aadc2c8d1a1421533) identifies v0.4.37. Its [variant manifest](https://github.com/devcontainers/images/blob/25ae116762a2dcbca01cf61aadc2c8d1a1421533/src/javascript-node/manifest.json) declares version 5.2.5 and 24-bookworm/amd64; its [Dockerfile](https://github.com/devcontainers/images/blob/25ae116762a2dcbca01cf61aadc2c8d1a1421533/src/javascript-node/.devcontainer/Dockerfile) derives from `node:${VARIANT}`. The [devcontainer definition](https://github.com/devcontainers/images/blob/25ae116762a2dcbca01cf61aadc2c8d1a1421533/src/javascript-node/.devcontainer/devcontainer.json#L7) enables common-utils:2, git:1, and node:2 features. The [common-utils source snapshot preceding the recorded build](https://github.com/devcontainers/features/blob/94181c0188ce13b8c145ab114e887715d45bd982/src/common-utils/main.sh#L60) lists jq for installation and configures passwordless root elevation for its development user.

The hash-linked SLSA subject agrees with the platform manifest and records the release source/workflow commit. Its dependency-completeness flag is false, and it does not bind the common-utils feature build-context digest. The feature snapshot is supporting source evidence, not proof of those exact feature bytes in the image. No independent signature/trust-root verification or complete feature-material chain was established.

### Runtime defaults and required proof

The config defaults to root with `docker-entrypoint.sh`; it declares no volumes or healthcheck. Its six public environment names are `PATH`, `NODE_VERSION`, `YARN_VERSION`, `LANG`, `NVM_DIR`, and `NVM_SYMLINK_CURRENT`. Source also introduces NVM/npm-global development configuration and passwordless sudo support. These are trusted image inputs, not operator authentication. The backend overrides numeric user/group to 1000, entrypoint, PATH, HOME, and npm configuration; other public inherited image variables remain present unless explicitly overridden. It does not claim a completely cleared image environment.

Retain no-new-privileges, capability drop, read-only root/source/index, no network or host mounts/sockets, fixed executable temporary/dependency mounts, quotas/deadlines, and continuous-storage cleanup. Require actual Bash/Git/Python 3/Node 24/npm/jq versions and a fixed jq JSON preflight before target code. In both target phases, require real jq behavior and a failed `sudo -n id -u` attempt with kernel `NoNewPrivs=1`, while preserving every existing canary and full Bootstrap check. A complete hosted run at the exact implementation head and final full-branch autoreview remain mandatory before readiness. No local runtime or VM was installed or started.
