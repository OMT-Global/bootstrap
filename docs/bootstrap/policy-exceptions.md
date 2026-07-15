# Policy exceptions

Declare every policy exception in `project.bootstrap.yaml` with an ID, policy,
scope, rationale, approver, and governing issue. Temporary exceptions require
an ISO `expiresAt` date; expired exceptions block validation. Exceptions expiring
within 14 days produce a `PRS-NOTIFY-001` notification intent and do not stop
work solely because they were reported.

Permanent exceptions require explicit approval and an `adr` reference. The
`bootstrap doctor` output reports deterministic `PRS-EXCEPTION-001` results so
automation can consume the same outcome as operators.

```yaml
exceptions:
  - id: temporary-runner-deviation
    policy: runner-policy
    scope: .github/workflows/release.yml
    rationale: Platform migration in progress
    approvedBy: release-maintainers
    issue: https://github.com/OMT-Global/bootstrap/issues/55
    expiresAt: 2026-09-01
```
