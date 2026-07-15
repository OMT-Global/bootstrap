# Language profiles

`bootstrap plan` detects repository markers before proposing changes. It selects
only the relevant profiles from TypeScript, Python, Rust, Go, Swift, Terraform,
Shell, SQL/SQLite, and documentation. Generated output is ignored during
detection, including `node_modules`, `dist`, `build`, `coverage`, and `.git`.

The plan reports a warning when the manifest archetype conflicts with detected
language evidence. For example, a `node-ts-service` manifest targeting a
Python-only repository reports the missing TypeScript profile while preserving
the detected Python profile. This is report-first: it does not rewrite the
manifest or execute project code.
