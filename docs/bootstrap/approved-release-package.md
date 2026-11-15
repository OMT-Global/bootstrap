# Approved release package prerequisite

This source-only prerequisite for issue #27 binds a validated approval manifest to
in-memory copies of the named release assets. It rejects missing, extra, duplicate,
wrong-sized, or wrong-digest assets, exposes immutable manifest-derived metadata,
and returns fresh copies of asset bytes. Package access fails after approval expiry.

The caller must independently authenticate the approval observation and artifact
provenance before invoking the producer. The producer does not authenticate GitHub,
obtain publication authority, verify a protected tag, isolate publish hooks, or
create or verify a release. Copies returned to a caller must be protected until
use. It holds full asset copies in memory, so callers must account for their size.

No checked-in workflow or command invokes this module. This prerequisite does
not enable automatic retries or complete issue #27.
