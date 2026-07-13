# Managed-file ownership

Every repository render writes `.bootstrap/managed-files.json`. The sidecar
identifies Bootstrap as the owner, records the template version and regeneration
command, and stores a SHA-256 digest for every managed artifact.

`bootstrap plan` and `bootstrap apply repo` reject a direct edit to a file that
Bootstrap previously managed. Restore the generated version, remove the file
from `repo.managedPaths`, or perform an explicit migration before changing the
managed set. This keeps product-owned files outside Bootstrap's authority and
prevents silent overwrites.
