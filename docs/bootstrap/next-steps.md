# Next Steps

- Add the primary runtime and package manifest for this project.
- Tighten `scripts/ci/run-fast-checks.sh` and `scripts/ci/run-extended-validation.sh` once the toolchain is known.
- Validate reusable control-plane workflows (`security-pr`, `release`, and AI attestation) before publishing a consumer-facing tag.
- Publish a stable control-plane tag or immutable SHA before moving Tier A repos off branch-ref callers.
- Review CODEOWNERS, environment reviewers, and required PR checks before the first merge.
- Re-run `bootstrap plan --manifest ./project.bootstrap.yaml` after major manifest changes to confirm intended drift.