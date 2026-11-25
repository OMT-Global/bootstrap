# Private approval state on S3

The read broker uses one versioned S3 state object per delegation and approval ID. Its key derives from the canonical IDs, independent of configuration epoch and request or operation ID. The approved deployment binding determines the state bucket, service KMS key and AWS account.

A verified request or revocation conditionally creates the initial state with `If-None-Match: *`. If an object already exists, the broker reads and validates the winner. A first revocation can win that race and leave a terminal tombstone. The broker does not need `ListBucket` to distinguish missing keys from existing state. S3 can return 403 for a missing key without that permission, so a denied read always fails.

Later transitions check the current record and replace it with `If-Match` on the observed S3 ETag. The adapter checks canonical record bytes, the exact derived key and configuration epoch, full SHA-256, versioned object metadata and the service encryption key. It allows only valid revision increments and state transitions. An ETag is a compare-and-swap token, while the checksum verifies the record bytes. A known conditional conflict can be handled by reading the winner. An ambiguous write acknowledgment fails closed with no automatic retry.

Each operation requires a live enrolled read-broker identity, a fresh signed configuration pointer and a temporary session scoped to the exact state object and operation. The state capability exposes no SDK client or credentials. It grants no listing, version deletion, retention override, payload access or client KMS unwrap. Approval state is mutable control data, separate from the objects that retain private evidence and audit events.

The coordinator still requires authenticated request, approval, revocation and audit evidence. Production composition must supply authenticated endpoint ingress, exact-version receipt and payload verification, client key use and durable signed audit acknowledgments. The fabricated AWS tests exercise request and response handling. They do not install provider policies or qualify production IAM, durability or clock health.
