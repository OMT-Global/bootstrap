import { execFile } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execute = promisify(execFile);
const repository = fileURLToPath(new URL("../", import.meta.url));
const source = path.join(repository, "src/native/upgrade-review-owner.py");
const fixture = path.join(repository, "tests/fixtures/review-native-owner-unit.py");
const python = process.platform === "darwin" ? "/opt/homebrew/bin/python3" : "/usr/bin/python3";
const environment = { PATH: "/opt/homebrew/bin:/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8", TMPDIR: process.platform === "darwin" ? "/private/tmp" : "/tmp" };
const options = { env: environment, timeout: 10_000, maxBuffer: 1_048_576, killSignal: "SIGKILL" as const };

const pythonCases = [
  "ProfileTests.test_current_fixed_review_arguments",
  "ParserTests.test_membership_preserves_exact_path",
  "ParserTests.test_membership_rejects_incomplete_or_multiple_hierarchies",
  "ParserTests.test_mount_identity_requires_one_full_root_cgroup_mount",
  "ParserTests.test_mount_metadata_cap_is_enforced",
  "ParserTests.test_bounded_read_accepts_exact_cap_and_rejects_next_byte",
  "ParserTests.test_duplicate_object_keys_are_rejected",
  "ParserTests.test_wrong_host_denies_before_reading_kernel_metadata",
  "MetadataEnvironmentUnitTests.test_constructor_keeps_only_three_metadata_fields_and_fixed_task_paths",
  "MetadataEnvironmentUnitTests.test_optional_metadata_absence_and_empty_values_preserve_presence",
  "MetadataEnvironmentUnitTests.test_unsupported_mode_presence_denies_before_any_value_or_path_read",
  "MetadataEnvironmentUnitTests.test_missing_relative_noncanonical_or_workspace_codex_root_is_denied",
  "CgroupOwnershipUnitTests.test_directory_ownership_is_exact_but_trusted_root_controls_remain_allowed",
  "FrameTests.test_roundtrip_complete_object",
  "FrameTests.test_fragmented_frame_survives_observation_timeout",
  "FrameTests.test_multiple_frames_remain_separate",
  "FrameTests.test_partial_eof_is_not_a_complete_frame",
  "FrameTests.test_frame_exact_cap_and_cap_plus_one",
  "FrameTests.test_receive_total_cap_counts_native_bytes",
  "FrameTests.test_send_total_cap_does_not_write_the_excess_frame",
  "FrameTests.test_malformed_frames_fail_in_real_owned_subprocesses",
  "StartAndCleanupTests.test_start_requires_exact_owned_layout_and_no_existing_reports",
  "StartAndCleanupTests.test_start_rejects_extra_input_and_noncanonical_scalar_types",
  "StartAndCleanupTests.test_start_rejects_symlink_or_publicly_writable_owned_directory",
  "StartAndCleanupTests.test_failed_constructor_closes_owned_descriptors_and_removes_only_created_leaf",
  "StartAndCleanupTests.test_collision_never_adopts_or_removes_foreign_leaf",
  "StartAndCleanupTests.test_occupied_scope_is_not_removed",
  "GuardianLimitUnitTests.test_all_selected_child_limits_are_checked_before_release",
  "GuardianLimitUnitTests.test_failed_limit_or_short_cpu_precondition_never_releases_helper",
  "CallerFailureUnitTests.test_cancel_kills_only_unreaped_guardian_before_claiming_owned_drain",
  "ProcessTests.test_actual_owned_child_wait_status_is_observed",
  "ProcessTests.test_expired_wait_kills_only_the_held_unreaped_child_and_reports_failure",
  "ProcessTests.test_barrier_requires_release_byte_and_eof_before_its_fixed_exec_boundary",
  "ProcessTests.test_barrier_parent_mismatch_denies_even_with_valid_release",
  "ProcessTests.test_entrypoint_propagates_clean_and_failed_main_status",
];

describe("G04 native-owner pure and owned-process regressions (not Linux qualification)", () => {
  it.each(pythonCases)("%s", async (name) => {
    const result = await execute(python, ["-I", fixture, source, name], options);
    expect(result.stderr).toContain("OK");
  });
});
