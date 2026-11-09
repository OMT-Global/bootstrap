# Verified Flow security response statements

Governing issue: [Bootstrap #63](https://github.com/OMT-Global/bootstrap/issues/63). Decisions: [ADR-0014](../decisions/ADR-0014-commonmark-security-response-statements.md) and [ADR-0015](../decisions/ADR-0015-managed-flow-security-projection.md).

Bootstrap checks public response statements against `policy.flow` for both managed and product-owned `SECURITY.md`. `repo.docs.security: false` preserves the product-owned document; managed selection renders the same verified commitments. It verifies the immutable policy reference, local bundle digest, compatible policy version, and four positive safe-integer response targets before comparing statements. No-policy document output and legacy checks retain their existing behavior. Managed Flow output additionally preserves the separate Bootstrap ten-business-day status update and ninety-day moderate target. This setting does not waive reporting, dependency, workflow, fork, CodeQL, SBOM, or capability checks.

This check recognizes a documented statement grammar. It does not establish prose intent, legal promises, operational response performance, or an SLA. Maintainers still review the policy and operate the response process. It neither changes Flow's published security policy nor applies repository settings.

## Supported CommonMark grammar

The original bounded document is parsed once by the JavaScript CommonMark reference implementation. Bootstrap neither renders the document to HTML nor strips inline syntax to reveal another statement.

A statement must occupy one complete paragraph. Its ancestors may be only the document, lists, and list items. Only immediate text, soft-break, and hard-break children are supported. A quote, heading, code block, inline code, emphasis, link, image, or unknown context cannot supply a statement. If a paragraph contains any unsupported inline child, that entire paragraph is ineligible; its remaining text is not promoted into a statement.

Separate promises require separate paragraphs or separate list items. Wrapped text inside one paragraph is joined with one ASCII space per soft or hard break. Bootstrap collapses ASCII horizontal whitespace, trims ASCII whitespace, permits one terminal period, and compares ASCII letters without regard to case. It does not fold Unicode letters, delete prefixes or negations, take substrings, or split one paragraph into several promises.

For example, the released Flow targets use these five separate list paragraphs:

```markdown
- Acknowledge a complete private report within 2 business days.
- Triage a confirmed report within 7 calendar days.
- Remediate or contain critical findings within 7 calendar days.
- Remediate high findings within 30 calendar days.
- Coordinate public disclosure with the reporter after remediation.
```

The four day counts come from the verified bundle. The business/calendar units and singular/plural spelling remain explicit. Medium/low timing is outside that four-target contract. An email or URI autolink makes its contact paragraph ineligible, but does not discard later separate promises.

The response document must be HTML-free CommonMark: any `html_inline` or `html_block` AST node anywhere makes the whole response document unsupported. This includes comments, CDATA, declarations, and raw HTML inside quotes. Literal tag text inside a code node remains code, and cannot supply a promise. The HTML rule is an intentional compatibility boundary, replacing the rejected experiment's HTML stripping behavior. No HTML ancestry or DOM visibility is inferred.

## File and resource boundary

Declared-Flow conformance chooses its reader before any generic `SECURITY.md` byte read. Supported text is reused for required-file presence and managed ownership hashes; unsupported or missing input blocks and withholds final generic planning. It opens the final file component with no-follow and nonblocking flags, inspects that opened handle, and requires a regular file with one link. A symlink, dangling link, hard link, directory, FIFO, device, or unsupported reader is rejected without a fallback reader. The containing repository directory remains the existing trusted target boundary.

The reader holds at most one 65,537-byte input buffer, accepts at most 65,536 bytes, and requires EOF within that limit. UTF-8 decoding is fatal on invalid bytes. Handles close on every success or failure path. File-size claims do not determine allocation, and oversized data is never truncated into an accepted document.

The complete document must satisfy every bound:

| Bound | Maximum |
|---|---:|
| UTF-8 input | 65,536 bytes |
| CommonMark CR, LF, or CRLF line boundaries | 2,048 lines |
| UTF-8 bytes in one line | 4,096 |
| Entered AST nodes | 32,768 |
| AST depth | 128 |
| Candidate paragraphs | 512 |

An exceeded bound, invalid UTF-8, unsupported file, parser error, or raw HTML produces a fixed blocking diagnostic. No partial statement set is accepted, and diagnostics do not expose document contents, absolute paths, OS errors, or stacks. These resource limits do not promise a hard execution deadline. Source line positions describe whole candidate paragraphs; inline source spans are not reconstructed.

A declared policy that fails verification blocks independently of document parsing; the checker does not fall back to generic clocks. Existing unrelated security checks and the reviewed exception policy continue to run. No new manifest field, CLI option, dependency, or exception is introduced. Pure `renderManagedFiles(manifest, resolvedPolicy)` callers must provide matching runtime-verified context when rendering managed SECURITY for a declared pin. Repository planning resolves the local bundle against `targetDir`, even with an external manifest path; invalid sources fail before application writes. Conformance reports unavailable dependent projections while independent controls continue. The shared declared-policy loader requires a relative path with lexical and resolved-parent containment inside the repository root, a no-follow/nonblocking opened regular singly linked file, fatal UTF-8, and at most 1 MiB with no truncation. Missing, malformed, unsafe, or oversized sources produce fixed sanitized errors. Direct plan/apply managed-file I/O retains its existing contract and is not a general special-file or filesystem-race defense.

## Runtime and attribution

The exact runtime dependency is `commonmark` 0.31.2, loaded through its documented CommonJS entry using `createRequire(import.meta.url)` and a typed boundary. The parser uses `smart: false`. Runtime/import validation must pass on the repository's minimum Node 20 as well as the available local runtime; a newer runtime succeeding does not establish Node 20 compatibility.

The exact development type package is `@types/commonmark` 0.27.10. The resolved runtime graph also includes entities 3.0.1, mdurl 1.0.1, and minimist 1.2.8. The [third-party inventory](third-party-inventory.md) records complete installed legal texts, their hashes, and the distinction between the original six-record owner confirmation and these four factual dependency additions. No upstream benchmark or specification fixtures are vendored.

The [CommonMark specification](https://spec.commonmark.org/0.31.2/) and [reference implementation](https://github.com/commonmark/commonmark.js) define the parser structure. Bootstrap's eligibility rules above deliberately select a smaller statement grammar from that structure.

The project-owned `.github/workflows/node20-compatibility.yml` job pins Node 20.20.2 on GitHub-hosted pull requests with read-only permissions. It performs locked installation without lifecycle scripts, typecheck/build, AST/reader/policy/conformance tests, and built CLI/module imports. It is a new compatibility-proof source, outside the generated asset projection; `ci.additionalWorkflows` only describes adjunct lanes and cannot generate this job, so no unsupported manifest declaration is added. The existing generated PR workflow is unchanged.

If historical or current Bootstrap ownership metadata still claims `SECURITY.md` after selecting the product-owned policy branch, conformance blocks for a manual ownership migration. It skips that leaf in generic ownership reads and withholds the generic planner while blocked; unrelated security, legal, profile, capability, and other managed-file checks continue. A reviewed, backed-up migration must preserve the product policy bytes. The checker neither edits ownership state nor deletes claims or transfers ownership implicitly.
