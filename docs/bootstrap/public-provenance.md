# Public Provenance

`bootstrap provenance create --input provenance-input.json --output provenance/runs/<run>.json` redacts metadata and writes the versioned public manifest. `bootstrap provenance validate --input provenance/runs/<run>.json` validates it before publication.

The public manifest records the repository, immutable commit SHA, workflow run, reviewer lineage, and safe metadata. It rejects credential-like literals; generators replace detected values with `[REDACTED:CREDENTIAL]` and record the replacement count.

This public contract deliberately does not include a private provenance sink, encryption material, bucket identity, or long-lived credentials. Those remain a separately reviewed issue #61 capability using short-lived runtime identity.
