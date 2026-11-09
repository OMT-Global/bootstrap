# Fleet upgrade admission prerequisite

The private admission and approval modules are the first J0 producer stage for [#62](https://github.com/OMT-Global/bootstrap/issues/62). They are not imported by the package index or CLI.

One 2 GiB logical pool in the canonical JavaScript global retains the debt of every admission account and failed approval preflight. Closing or serializing an account does not release credit. Accounts carry no execution permission, and a second module instance in that global cannot start another ledger. This stage does not coordinate worker threads or VM realms; the separate trusted-startup gate must establish supported single-global use before execution.

Offline authentication uses only `/etc/bootstrap/upgrade-journal/approved-installation.v1.json` and its fixed evidence directory. The strict canonical manifest requires two distinct pinned Ed25519 approval roles, exact bounded inventory and evidence associations, and checked file ancestry. Production anchors are empty. File ownership, a JSON success field, a test key or caller configuration cannot substitute for an independently authenticated approval.

`AuthenticatedApproval` means that the selected statements authenticated. It does not mean that installation, startup, storage or hardware measurements passed. The real measurement/startup producer, owned-child recovery, independent cleanup support, durable journal ACK, shared B integration and full executor proof remain unavailable. No apply, publication, provider, signing or native-runtime route is enabled here.

See [ADR-0024](../decisions/ADR-0024-fleet-upgrade-admission-and-approval.md) for the boundary and remaining gates. Tests use isolated source copies and fabricated approval evidence; they cannot activate the production module or establish storage durability.
