# Fleet Policy Upgrades

Use `bootstrap upgrade-plan --input inventory.json --json` to produce a non-mutating inventory before opening any upgrade PRs.

Each inventory entry records repository, class, current and target exact SemVer policy versions, optional exception, and pilot outcome. Patch upgrades become eligible only after a passing first representative per class; failed pilots block the remaining class batch. Minor upgrades require independent review; major upgrades require notification and an accepted ADR.

This planner deliberately does not create PRs or merge upgrades. Operators must attach policy diff, validation, exceptions, and provenance evidence to the governed PR after the dry run is approved.
