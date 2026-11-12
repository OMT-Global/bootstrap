# ADR-0051: Public fleet discovery with a supplied read capability

Status: Accepted

Date: 2026-11-11

Decision owner: Bootstrap maintainers

Decision record: The repository owner selected a dedicated GitHub App with short-lived scoped tokens as the direction for the governed fleet route. This source-only decision extends the anonymous discovery in ADR-0035; it does not approve installing the App, acquiring or using a real token, or publishing an upgrade.

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62).

## Decision

Keep complete public organization enumeration anonymous, both before and after inspection, so a token restricted to a subset of repositories cannot silently narrow the enumerated public fleet. An optional read capability supplied by trusted in-process code may accompany the fixed GitHub API GET requests used to inspect public repository identities and immutable Git objects. The discovery operation never performs a write or reads credentials from the environment, a file, Git configuration or a keychain. Without a supplied capability, retain the existing anonymous behavior.

The token is transmitted only in an authorization header to the fixed HTTPS GitHub API origin; redirects are rejected. Reject malformed, control-bearing or oversized token strings before any request, and never put the token, response body or transport error text in the returned report. Unexpected authorization, pagination, object or transport failures yield an incomplete report, and incomplete reports do not release retained manifest text. Public visibility, owner and repository identity, Git object binding, bounded parsing and end-of-scan rechecks remain required.

## Trust boundary and consequences

The token string is a capability, not proof of an App identity, installation, expiry, repository scope, or least privilege. A separately reviewed trusted broker must mint and validate the intended short-lived installation token and enforce its read-only authority; this function cannot verify those claims from the string. An App installation that cannot read a public object may cause an incomplete result; it must not convert the repository into unmanaged or eligible. A successful public-object read also does not prove that the token can write that repository.

The in-process caller, built-in `fetch`, DNS, TLS implementation and broker remain trusted. A caller with arbitrary process control can observe memory or replace the transport. JavaScript strings cannot be reliably wiped. The operation's bounded input accounting does not certify native allocation or protect against the same-process caller. Use no real credential until the broker and execution environment have separate authorization and review.

The `discover-public-fleet` command emits a human-readable or JSON report and exits nonzero for incomplete discovery. Public manifests that normalize successfully may contribute the normalized class, a safely renderable Flow ref and declared digest, and an exception count; these claims are not verified policy or exception evidence. This extends ADR-0035's original no-CLI source stage without activating an executor. It is anonymous unless the operator explicitly supplies a read capability on nonterminal standard input. It never opens a capability file or reads one from an argument, environment variable, Git configuration, or keychain. The standard-input mode cannot establish that the capability came from an App broker. It applies a byte limit and timeout, rejects malformed inputs and terminal entry, and emits only generic input errors. Buffer clearing is best effort; JavaScript string lifetime is not controlled.

This source stage adds no token broker, private-key handling, protected-runner configuration, app installation, provider mutation or PR publication. It does not validate policy versions, drift, exceptions, pilot evidence or upgrade eligibility. The next implementation must connect complete observations to authenticated, independently reviewed policy and pilot evidence before authorizing any change.
