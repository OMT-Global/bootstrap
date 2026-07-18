# Managed-file ownership

Every repository render writes `.bootstrap/managed-files.json`. The sidecar
identifies Bootstrap as the owner, records the template version and regeneration
command, and stores a SHA-256 digest for every managed artifact.

The mutable tracked sidecar is a reviewable ownership claim, not independent
authority to overwrite or delete repository content. Machine-local state is the
trusted baseline for destructive updates and removals. Without that baseline,
`bootstrap plan` accepts unchanged projections but fails closed on claimed-file
updates, missing files, and stale-file removal; re-establish state from an
unchanged projection or perform an explicit migration before changing the
managed set. This keeps product-owned files outside Bootstrap's authority and
prevents silent overwrites.
