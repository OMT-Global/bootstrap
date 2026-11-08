# Private fleet host brokers

This prerequisite for [#62](https://github.com/OMT-Global/bootstrap/issues/62) adds internal public-history, signing and create-only publication capabilities. It exposes no CLI or package-index operator path. See [ADR-0017](../decisions/ADR-0017-bounded-fleet-host-brokers.md) for supported host, source, signer, provider and recovery contracts.

The initial host profile requires unprivileged Linux x64, fixed trusted Git/HTTPS/prlimit tools, and the accepted resource ceilings. Public GitHub history must be complete within the depth/object/pack bounds. The 2 GiB host preparation ceiling is conservative logical admission, not a disk quota or a guarantee that every 512 MiB source fits. Unsupported hosts, histories, signing/configuration layouts or provider contexts fail closed.

Run normal typecheck, tests and build through `bash scripts/ci/run-fast-checks.sh`. The default tests use private synthetic repository/API adapters and ephemeral test SSH keys/agents. They never read the operator's key, probe the operator's agent, authenticate to GitHub, or publish a real ref/PR. Git-only Darwin tests do not demonstrate Linux kernel enforcement.

The registered full release-validation route additionally requires:

```sh
BOOTSTRAP_REQUIRE_HOST_BROKER_TESTS=1 npm test -- \
  tests/upgrade-host-linux.test.ts tests/upgrade-transport-linux.test.ts \
  tests/upgrade-brokers-integration-linux.test.ts tests/upgrade-publication.test.ts \
  --maxWorkers=1 --minWorkers=1
```

Required mode fails when Linux/tool/resource/backend prerequisites are absent; it never converts missing proof into success. The host suite exercises actual inherited FSIZE/CPU/address/descriptor/process/deadline controls. The transport suite exercises controlled large/compressed ordinary Git objects under real limits. The composition suite uses the real isolated backend, exact frozen candidate, supported public hook and ephemeral SSH signing. The publication suite additionally requires actual wrapper startup under the same Linux address-space/resource limits with a synthetic provider. Synthetic network routing supplies only fabricated public history while retaining actual Linux process limits. No real operator authentication or publication is part of these proofs.

Keep the exact tested head, commands, output and immutable runtime artifact in PR validation evidence. A clean source review or an older backend-only Docker run is not proof for this stage. The later supervisor remains responsible for fixed-point ownership, full phase ordering, independent candidate review, original preservation and truthful report-before-failure behavior.

Publication failures may leave a verified signed candidate, an uncertain or confirmed remote ref, and a known draft PR URL. Preserve that recovery context. Do not retry by overwriting or deleting the existing branch. Cleanup removes only owned ephemeral plumbing and never changes the original checkout or rolls back successful public state.
