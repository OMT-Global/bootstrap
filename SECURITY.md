# Security Policy

## Supported Surface

This repository follows the bootstrap-managed security baseline for OMT-Global/bootstrap.

## Reporting

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/OMT-Global/bootstrap/security/advisories/new). If that form is unavailable, open a public issue titled `Private security contact requested` without vulnerability details; maintainers will establish a confidential channel before accepting the report. Never include exploit details in public issues or discussions.

## Response Targets

- Acknowledge a complete private report within 2 business days.
- Triage a confirmed report within 7 calendar days.
- Remediate or contain critical findings within 7 calendar days.
- Remediate high findings within 30 calendar days.
- Coordinate public disclosure with the reporter after remediation.
- Provide a status update within 10 business days, even when investigation is ongoing.
- Bootstrap additionally targets remediation within 90 days for moderate findings. Low-severity findings are scheduled by maintainers.

## Baseline

- Dependabot policy: enabled
- Secret scanning hints: enabled
- Generated hooks and CI helpers must not require committed secrets or machine-local environment files.
