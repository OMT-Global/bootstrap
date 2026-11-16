# Public fleet inventory

Issue #62's read-only inventory connects public discovery, verified Flow policy
sources, deterministic managed outputs and the existing upgrade planner:

```sh
bootstrap inventory-public-fleet --org OMT-Global \
  --target-ref refs/tags/v1.2.3 --target-sha256 <approved-policy-digest> \
  --generator-root /absolute/trusted/bootstrap --generator-commit <exact-sha>
```

The selectors above are placeholders, not a release or rollout recommendation.
The default emits human-readable output; add `--json` for schema version 1 JSON.
There is no apply or PR-creation mode. No repository hooks, target scripts,
workflow dispatches, App installation, token minting or GitHub writes run.

The supplied generator checkout must satisfy the existing Linux capture
contract, including clean tracked bytes at the selected commit and supported
Git/configuration/filesystem state. Capturing tracked source does not attest the
installed runtime or dependencies. An unsupported host or generator produces an
incomplete result, not an alternate weaker capture. The integration tests use
real temporary Git objects and fabricated HTTPS responses, while simulating
Linux eligibility and `prlimit`; they do not prove real Linux isolation.

Organization enumeration stays anonymous. Optional `--read-token-stdin` uses the
existing bounded nonterminal input reader for a separately supplied trusted
public-read capability. It never consults ambient tokens, auth files, Git
credentials or a keychain. That string does not prove App issuance, expiry or
scope. Each policy/drift reader sends it only to its selected repository;
independent Flow policy reads remain anonymous unless Flow is that repository.
The final shared publisher-binding check is anonymous. A denied request does not
fall back to anonymous. Real credential use still
needs an authorized broker/runtime. Rate limits produce an incomplete report.

The command derives class, source/target policy versions and immutable pin
bindings from owned policy observations. Versions come from validated policy
contents, not release-tag names. It preserves the selected digest algorithm.
Every declared exception is included; approval, notification and ADR claims in
those public declarations are not independently authenticated by this command.

For drift, the current source policy is rendered through the selected generator.
Every selected rendered path is read by verified Git object identity, with bytes
and executable mode compared. A missing path is reported only after a complete
validated tree proves absence; HTTP 404/denial is an incomplete observation.
Legal template and existing legal bytes are projected through the existing
license logic in private temporary scratch space. The exact ownership sidecar
is compared too. Alternate legal files, special root entries affecting that
projection, unverifiable legal transitions, malformed ownership and extra
sidecar claims stay unsupported/incomplete with explicit unassessed paths.
The scratch copy is deleted; no target repository state is written and no legal
or ownership-transition authority is created. Project-owned legal files with
no managed-policy/sidecar claim are outside the managed drift scope.

Each repository is rechecked around drift collection, and complete discovery is
repeated after the fleet scan; observed policy tag bindings and publisher identity
are checked again. Membership, visibility, flags, default branches,
heads or manifest changes invalidate the result. Earlier detailed rows are
cleared when the final observation window is rejected, leaving their prior
public name/ID and incomplete reason. These are repeated observations, not an
atomic fleet snapshot or a guarantee against later changes.

The inventory has a five-minute aggregate deadline, a 10,000-request accounting
limit, a 256 MiB response accounting limit and 250 candidate paths per managed
repository, in addition to the existing adapters' limits. Before a phase it
reserves that adapter's bounded capacity (5,000 discovery requests or 500 policy/
drift requests, plus a locally rejected over-limit attempt); after a phase it
checks actual accounting. Exhaustion or incomplete collection exits nonzero.
Unmanaged repositories remain visible in the report. Unsupported rows are not
silently removed to make the inventory appear complete.

Only verified version candidates enter the planner, with pilot outcome fixed to
pending. Existing-head CI is not an upgrade pilot. Multiple exceptions remain
in the report even though the legacy planner accepts one exception identifier;
any such candidate retains its exception review gate. An incomplete inventory
cannot select an eligible pilot or batch. Even a complete inventory confers no
write authority or patch auto-merge permission.

The integrated publisher, isolated candidate validation, independent review,
authenticated pilot outcome records and uncertain-write recovery still remain
under #62. This command does not complete those acceptance criteria.
