# ADR-0030: Immutable release verification and publication primitives

Status: Accepted

Acceptance covers the root-adopted primitive source stage. Required code review, human PR approval, hosted validation and release-content approval remain separate.

Date: 2026-11-09

Governing issue: [#27](https://github.com/OMT-Global/bootstrap/issues/27).

## Context

An exact release tag binds a source commit, but a run/name download can select a replacement package after a rerun. Source identity alone does not identify the exact independently approved package bytes. Issue 27 therefore needs an independent artifact instance and stored-ZIP digest, followed by consumers that preserve that identity through publication and verification.

The complete correction exceeds the repository's 800 changed code/configuration line limit. Root adopted a prerequisite containing complete, testable primitives, followed by named producer/publish, postpublish and repository-adoption consumers. The explicit critical `RELEASE_BLOCKER` scope exception covers this demonstrated approval-binding gap; it does not waive the hard 800-line limit. The current scoped P projection contains 422 counted canonical additions. Each actual PR must recount all canonical/generated code and sidecar changes against its real base.

## Decision

Add the canonical verifier and publication-planner factories to `src/archetypes.ts`, with tests invoking the actual factories. P changes no managed output, manifest, ownership state, caller pin or running workflow. Defining or importing a factory does not activate its generated Python or authorize an artifact, release or deployment.

The future strong contract uses an independently approved tuple of repository, preflight run ID, artifact ID and expected raw ZIP SHA256. Canonical positive decimal selectors remain lossless; native API identities require exact integer values and reject booleans/coercion. Resolve the exact artifact, require matching repository/run/name/expiry/metadata digest, and hash the actual stored ZIP through its held file identity before parsing. Deletion, unavailable evidence or a mismatch fails without a name/latest/rebuild fallback.

Strong execution requires POSIX CPython 3.12 or newer, isolated with `-I -S`, and the required descriptor/no-follow APIs. This capability is probed and fails closed; P installs no runtime or runner policy. Extraction validates original names, local/central consistency, ordinary types, duplicate/prefix conflicts and actual filesystem aliases. It streams STORED/DEFLATE members with complete EOF, size and CRC checks, accepts supported ZIP64/data-descriptor forms, and creates exclusive contained files. Descriptor widths follow local/central size sentinels and resolved sizes; an offset-only central ZIP64 field does not widen 32-bit descriptor sizes. Signed and unsigned descriptors, including forced local ZIP64 with zero-filled streamed size values, remain supported under the [PKWARE ZIP format contract](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) and [CPython writer behavior](https://github.com/python/cpython/blob/v3.12.7/Lib/zipfile/__init__.py). No partial tree is published and no new expansion quota is claimed.

The approved evidence carries a canonical string `run_attempt` stamped before upload. Require that exact historical attempt to have completed successfully. API/artifact platform heads agree with each other; the checked-out package target separately agrees with the exact release tag. Neither platform head nor event `GITHUB_SHA` must equal that target. Artifact metadata has no attempt field, so the trusted producer's stamp inside independently digest-approved bytes remains an explicit assurance boundary.

The verifier derives a canonical regular-member digest map outside the ZIP. Before a custom publish hook, the planner binds notes and every checksum-manifest reference to that map, checks declared/consumed digests, rejects absent or ambiguous references, and reserves all flattened destinations exclusively. Trusted configured absolute/relative artifact prefixes may map to canonical member tails; strong mode has no basename fallback. Checksum entries use the existing producers' [untagged checksum format](https://www.gnu.org/software/coreutils/manual/html_node/cksum-output-modes.html): 64 lowercase hex characters, a literal space, the text-space or binary-asterisk marker, then the unchanged filename. LF terminates a record; blank-only records are ignored. Filename whitespace is retained, and escaped records fail closed without a new filename codec. The verified SHA256SUMS member is a staged release asset independently of its entries: its reserved flat name cannot collide with another selected member, and its bytes and destination identity receive the same post-hook checks as ordinary assets. A manifest without ordinary selected assets still fails. Reservation detects actual filesystem name collisions without imposing casefold or Unicode-normalization bans.

The private plan records expected member digests and reserved file identities. After the hook, copy rechecks source bytes and destination identities while streaming, then emits the complete NUL-separated asset list. Strong CLI notes use a verified private notes file; the configured notes reference remains available before the hook. These checks provide no sandbox against malicious code running as the same operating-system user.

F1 is part of this primitive contract: normalize each final CLI asset operand to an absolute path and reject `#`, `*`, `?`, `[` and POSIX backslash anywhere in that operand, including its temporary parent, before the hook. Qualified GitHub CLI source splits labels at the first `#` and applies glob grammar to other operands even when a literal file exists. Bare `]`, spaces, Unicode and dash basenames receive no additional transport ban. Shell quoting and NUL framing alone do not disable the CLI parser.

## Named consumers and compatibility

G1 follows landed P. It stamps the producer attempt before upload, exposes artifact ID/digest after upload outside the ZIP, and wires the optional strong publish API to these primitives. G2 follows landed G1 and wires the same verifier into standalone postpublish. Neither needs another canonical Python copy or a new managed helper path.

H follows the actual landed G2 main commit and adopts that capable immutable pin, callers and project-owned source-release hook. A measurement placeholder is never a usable production pin. H retains independent package/publication comparison and the four-asset source-release contract. F2 belongs to that H schema boundary: boolean schema/count values must be rejected while preserving equivalent JSON numeric `1.0` behavior where the predecessor accepted numeric `1`.

Future strong selection activates when its boolean is true or either new selector is supplied. Absent/false with empty selectors retains the existing legacy branch and executes no Python. Generic optional hooks, existing validation-run source/repository/run/current-success checks, permissions and the unchanged full-validation reusable remain separate contracts.

## Consequences and gates

The existing 47 managed paths, three project-owned release hooks, README and governed legal boundary remain intact. P adds no provider, permission, manifest control mode, managed path, settings/home change or publication action. Following managed stages require their own genuine state, doctor/plan evidence and reviewed repository-only generation; a scratch projection or copied state is not apply authority.

Actual factory regressions and repository-required typing, tests, build and independent review remain implementation gates. Root obtains exact scoped authorization before transmitting the intended diff to the installed model reviewer; this ADR supplies no such authorization or review result. Current-head human approval, CI/conversation checks and capable-pin byte verification remain required. None of these source stages approves release contents, creates a tag, uploads assets or closes the remaining issue 27 acceptance by itself.
