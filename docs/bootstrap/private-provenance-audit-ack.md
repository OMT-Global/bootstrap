# Private audit acknowledgment signing

The enrolled audit worker signs an acknowledgment only after its own authenticated, conditional audit write has been read back by exact S3 version. The signer accepts the original verified storage result from that worker's identity on the same live TLS connection. The result is single-use and expires with the bounded audit admission. A copied or reconstructed object cannot authorize signing.

The current root-signed deployment selects a custody descriptor for the worker's enrolled `audit-ack` key. The descriptor pins the S3 object version and wrapped-key digest. The isolated custody lease can read that exact version and unwrap only the configured custody KMS key with the exact `audit-ack` purpose, owner, key fingerprint and epoch context. The original config-only lease refreshes current configuration. The worker checks the derived Ed25519 public key and clears temporary SDK plaintext before retaining the in-process private key object.

Before signing, the worker rechecks the broker's native run, active config, audit age and exact 90-day retention recorded by the verified write. It signs the existing canonical audit acknowledgment and independently verifies the signature under the enrolled audit key. The signed fields bind event, operation, phase, storage version and configuration epoch. Missing custody, expired or copied evidence, failed verification and a disconnected peer produce no acknowledgment. The signing layer does not retry a write or substitute an acknowledgment for missing durability.

The HTTP framing and broker-side transport still need fixed application wiring. Local tests use fabricated provider responses and ephemeral keys. Provider policy, key enrollment, and protected deployment require separate qualification.
