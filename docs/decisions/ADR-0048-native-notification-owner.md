# ADR-0048: Native notification ownership

- Status: accepted bounded source contract; protected-default implementation stage1 only
- Governing issue: #62
- Source anchor: `2ee77123ca5591ab1638cd63bdbad46f32c081cd`

## Context

The current ordinary `deliverMaterialAction` is a real consumer of the protected default webhook sender. Previously it called `end` before TLS establishment, acknowledged response `end` without owning request/message/socket close, imposed no finite native response/framing limits, and retried any failed address. A failed request could have sent a POST, so a later successful address could conceal an earlier ambiguous effect. OS lookup timeout used a Promise race that did not drain the underlying lookup.

ROOT adopted the independently CLEAN bounded N design revision3 (candidate SHA256 `38f9c026fa83124bab443139ddc8fa7103b209b6b5760f5359e98c8181213f98`, final review manifest `7a01360adcd2513936d3a12c1cbbbc93d6badf9171f0294eed3438de3c51fe6c`). This source stage implements the existing protected default only. The later N producer, private context/shared aggregate ledger, parent process, genuine applicability/set/effect grant and G07/first-apply joins remain separate work.

## Stage1 decision

Preserve the public delivery options/report shape, both required destinations, existing category meanings, human hard-stop checks and actual comment/webhook body generation. The default resolver remains OS `lookup` with the complete answer validated before any connection:1..64 addresses, matching IPv4/IPv6 family and all public under the existing blocklists. Preserve HTTPS443, no userinfo, the executor hostname allowlist, pinned lookup and TLS identity. No new environment/configuration/profile propagation or backend option exists.

Use one standard-monotonic ten-second permission deadline covering actual lookup, all address attempts, send, body and close. No address gets a new allowance. The actual default lookup remains owned until settlement; an expired lookup cannot start HTTP afterward. Existing explicitly injected legacy resolvers retain their previous bounded-wait behavior and are not used by the future N path.

The actual default sender creates direct HTTPS with agent disabled, TLS1.2 minimum, certificate verification, identity accept encoding and connection close. It invokes no write/end/flushHeaders until the owned socket's verified secureConnect gate. It marks possible-send before its sole end(body). A timeout/error/incomplete response after that point is sticky and never causes another address attempt. Only an actually closed request/socket with no write/end/flush, no sent headers and zero inbound plaintext HTTP bytes may fall back within the same deadline. An exception or timeout alone is insufficient.

A response is acknowledged only after complete HTTP/1.1 framing/body/end AND actual request/message/socket close. Bound JSON POST bytes at64KiB, raw response headers at32KiB, body at1MiB and total plaintext HTTP wire at1MiB+32KiB. Opaque response bodies are not decoded or decompressed. Accept exact content-length, close-delimited, or bounded standard chunked framing where a body is permitted;204 cannot carry transfer encoding; unsupported chunk extensions, trailers, duplicate headers, informational/upgrade responses, redirects/Location, invalid lengths, truncation and extra raw bytes fail closed. A private fixed-size wire buffer permits complete framing validation and is discarded after settlement; it is not a response payload/report field. A2xx status or body end alone creates no acknowledgement.

Failure destroys every observed owned request/message/socket and waits actual close. The ordinary default does not own an enclosing process: an unresponsive OS lookup or socket can therefore delay failure return beyond ten seconds. The deadline limits permission and prevents a late successful acknowledgement or send; it is not a hard drain-time guarantee. The later N parent must provide actual process containment under its separately adopted90s owner. No Promise race, timer clear, signal-send, Darwin source test or event fixture supplies that proof.

## Verification and remaining gates

Synthetic Node HTTP-event fixtures exercise the actual default resolver/sender through real delivery logic with fabricated DNS/HTTPS events, independent held-close schedules and no external network or account. They verify normal opaque/204/chunked delivery, failure-return ownership, no-send fallback, sticky ambiguous sends, complete answer and byte/framing limits, and expiry during lookup/close. These tests are source regressions; matching Linux/TLS/DNS/process qualification is unexecuted.

Preserve the future source runtime contract: trusted current Node executable, sole `--use-openssl-ca` flag and unchanged1GiB address-space/resource limits. This stage neither launches that N worker nor certifies its native eligibility. Actual credentials/routing values, both notification effects, external diff review, push/PR and original issue62 completion remain separately gated.
