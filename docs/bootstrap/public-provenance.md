# Public Provenance

`bootstrap provenance create --input provenance-input.json --output provenance/runs/<run>.json` redacts metadata and writes the versioned public manifest. `bootstrap provenance validate --input provenance/runs/<run>.json` validates it before publication.

The public manifest records the repository, immutable commit SHA, workflow run, reviewer lineage, and explicitly allowlisted metadata. The only metadata keys accepted are `policy`, `generator`, `aiProvider`, `aiModel`, `promptHash`, and `changeClass`; unknown keys and unknown fields at any schema boundary fail validation rather than being copied or silently removed.

Credential-like literals in allowlisted metadata become typed `[REDACTED:CREDENTIAL]` placeholders. Validation rejects credential-like values in identity fields and rejects redaction counts that do not exactly match the emitted placeholders. The detector is defense in depth, not permission to pass arbitrary logs, prompts, tool output, customer data, or other private material into the public generator.

This public contract deliberately does not include a private provenance sink, encryption material, bucket identity, or long-lived credentials. Those remain a separately reviewed issue #61 capability using short-lived runtime identity.
