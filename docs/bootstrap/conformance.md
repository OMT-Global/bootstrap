# Conformance core

`bootstrap conform` produces deterministic, versioned JSON and human output for
the Public Repository Standard conformance core. Each result includes a stable
rule ID, severity, evidence, and remediation. Blocking findings set exit code
`1`; warnings remain distinct and return `0`.

The first core validates repository class and product maturity, language-profile
conflicts, typed exceptions, and the managed-file ownership sidecar. Additional
security, provenance, GitHub-plan capability, and waiver rules can extend the
same report schema without changing existing result semantics.
