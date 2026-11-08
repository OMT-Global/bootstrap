# Standalone postpublish preflight input

The generated reusable postpublish workflow accepts an optional string `preflight_run_id`, defaulting to an empty string, and passes it to the verification hook as `PREFLIGHT_RUN_ID`. Existing callers can omit the input.

`release.postpublishRequiresPreflight` is a strict boolean selector with default-off behavior. When omitted or `false`, the standalone caller remains byte-identical to the legacy caller and does not send a new argument to older pinned reusables. An omitted selector also remains absent from normalized manifest output.

Set the selector to `true` only after selecting a reviewed immutable `release.reusableWorkflowRef` that declares the optional input. The standalone dispatch then requires an explicit `preflight_run_id` and forwards that exact value. The generator does not discover an approved run from a workflow name or the latest run. The verification hook remains responsible for validating the supplied run and its evidence.

This source prerequisite does not enable the selector in Bootstrap, change its existing reusable pin, update checked-in workflows or release hooks, or publish a release. Those adoption changes require their own coherent review. The existing publish reusable's `PREFLIGHT_RUN_ID` forwarding is preserved.
