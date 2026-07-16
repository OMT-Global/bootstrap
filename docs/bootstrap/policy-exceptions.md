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

## Material-action notifications and hard stops

Configure the second required notification destination by naming the
environment variable that contains its webhook URL. Store only the variable
name in the manifest; the URL and any secret-bearing routing token remain in
the execution environment. The executor must also set the fixed
`BOOTSTRAP_NOTIFICATION_WEBHOOK_ALLOWED_HOSTS` variable to a comma-separated
allowlist of exact webhook hostnames. The manifest cannot select or replace
this allowlist.

```yaml
notifications:
  webhookUrlEnv: BOOTSTRAP_NOTIFICATION_WEBHOOK_URL
```

```sh
export BOOTSTRAP_NOTIFICATION_WEBHOOK_ALLOWED_HOSTS=hooks.example.com
```

Delivery accepts only HTTPS on port 443, resolves every allowlisted hostname
before connecting, and rejects loopback, link-local, private, multicast, and
reserved addresses. The built-in transport pins a validated public address for
the TLS connection so a second DNS lookup cannot rebind the destination.

Describe one material action in a JSON file. The governing target accepts a
local issue or pull request such as `#55`, an `owner/repo#55` shorthand, or a
full GitHub issue or pull-request URL.

```json
{
  "id": "release-policy-2026-07-16",
  "action": "repository-settings-change",
  "summary": "Enable private vulnerability reporting.",
  "governingTarget": "#55"
}
```

Plan before delivery:

```sh
bootstrap notifications plan --manifest project.bootstrap.yaml --input material-action.json
bootstrap notifications deliver --manifest project.bootstrap.yaml --input material-action.json
```

Bootstrap also converts the manifest's expiring-exception intents directly.
This is plan-only unless `--deliver` is explicit:

```sh
bootstrap notifications exceptions --manifest project.bootstrap.yaml
bootstrap notifications exceptions --manifest project.bootstrap.yaml --deliver
```

All notification commands support `--json` and return stable `PRS-NOTIFY-001` and
`PRS-HARDSTOP-001` results. Delivery writes the redacted notification to the
governing GitHub issue or pull request and to the configured HTTPS webhook. A
failed destination blocks continuation.

For a defined hard stop, add its category plus explicit human approval
evidence. Planning and delivery remain blocking until both fields are present:

```json
{
  "id": "license-change-2026-07-16",
  "action": "license-change",
  "summary": "Apply the approved repository license change.",
  "governingTarget": "https://github.com/acme/example/issues/55",
  "approval": {
    "evidence": "https://github.com/acme/example/issues/55#issuecomment-1"
  }
}
```

The evidence comment must be on the governing issue or pull request, authored
by a configured `github.reviewers` maintainer, and contain this exact marker:

```text
APPROVE PRS-HARDSTOP-001 action=license-change-2026-07-16 category=license-change digest=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The action category is the canonical Flow hard-stop category; there is no
separate caller-controlled hard-stop flag. Planning records that verification
is required and returns the canonical `approvalDigest`; copy that exact digest
into the approval marker. The digest binds the action ID, category, summary,
and governing target so approval cannot be replayed after any of those fields
change. Delivery fetches and verifies the GitHub comment before returning an
approved result.

Notification delivery still occurs for a blocked hard stop so the governing
record captures the request. Work continues only when both required
destinations succeed and the hard stop has explicit approval evidence.
