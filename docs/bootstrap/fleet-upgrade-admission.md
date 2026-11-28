# Fleet upgrade admission prerequisite

The private admission and approval modules are the first J0 producer stage for [#62](https://github.com/OMT-Global/bootstrap/issues/62). They are not imported by the package index or CLI.

One 2 GiB logical pool in the canonical JavaScript global retains the debt of every admission account and failed approval preflight. Closing or serializing an account does not release credit. Accounts carry no execution permission, and a second module instance in that global cannot start another ledger. This stage does not coordinate worker threads or VM realms; the separate trusted-startup gate must establish supported single-global use before execution.

Offline authentication uses only `/etc/bootstrap/upgrade-journal/approved-installation.v1.json` and its fixed evidence directory. The strict canonical manifest requires two distinct pinned Ed25519 approval roles, exact bounded inventory and evidence associations, and checked file ancestry. Production anchors are empty. File ownership, a JSON success field, a test key or caller configuration cannot substitute for an independently authenticated approval.

`AuthenticatedApproval` means that the selected statements authenticated. It does not mean that installation, startup, storage or hardware measurements passed. The real measurement/startup producer, owned-child recovery, independent cleanup support, durable journal ACK, shared B integration and full executor proof remain unavailable. No apply, publication, provider, signing or native-runtime route is enabled here.

See [ADR-0024](../decisions/ADR-0024-fleet-upgrade-admission-and-approval.md) for the boundary and remaining gates. Tests use isolated source copies and fabricated approval evidence; they cannot activate the production module or establish storage durability.

## Factual view lifetime and allocation limits

An unchanged immutable admission view may reuse its identity. A changed view pays for a new copy in the same pool and may report `admission-exhausted` when credit is unavailable; an old view is never presented as current. Every account prepays its first close result before work. That first close revokes further work even at the ceiling, without a new reservation. Later observations of a closed owner may spend process metadata credit but cannot reopen the account or refund debt.

Reservation denials reuse startup-funded fixed errors. Authentication setup funds its fixed errors, unsupported results and settled denial promises through an internal fixed process debit with no caller amount or authority output. Accepted async authentication and recheck entries reserve against their genuine account before entering the async body. Repeated denied entries create no fresh account, result or promise. Poisoning remains permanent, and only its first transition closes the account.

The 512-, 4096- and 65536-byte allowances are conservative logical charges. They do not certify the selected runtime's object, Map, native, allocator or RSS bounds. New owned representations and framing still need coverage; preexisting foreign runtime state and physical GC copies are separate runtime proof questions. All original startup, checked-close, native, installation and full-executor gates above remain unresolved. The concurrency regression uses synthetic scheduling around actual fixture filesystem calls; it is no OS, storage or hardware qualification.
