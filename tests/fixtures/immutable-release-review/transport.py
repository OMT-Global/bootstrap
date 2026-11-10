from pathlib import Path
import hashlib
import io
import json
import os
import subprocess
import sys
import zipfile

program, scenario, temporary, *shell = sys.argv[1:]
root = Path(temporary)
root.mkdir(exist_ok=True)
tree = root / "files"
tree.mkdir()
stage_name = {"hash-parent": "stage#label", "star-parent": "stage*", "question-parent": "stage?", "class-parent": "stage[0]", "backslash-parent": "stage\\escape"}.get(scenario, "stage")
stage = root / stage_name
stage.mkdir()
names = {"distinct-hash-label": ["x", "x#label"], "star-name": ["x", "x*"], "question-name": ["xA", "x?"], "class-name": ["x0", "x[0]"], "space-name": ["with space"], "unicode-name": ["café"], "right-bracket-name": ["right]name"], "dash-name": ["-dash"], "normal-name": ["x"], "checksum-only": [], "checksum-flat-collision": ["nested/SHA256SUMS"]}.get(scenario, ["x"])
payloads = {name: ("owned-" + str(index)).encode() for index, name in enumerate(names)}
payloads["RELEASE_NOTES.md"] = b"notes"
prefix = str(root / "configured-output")
checksum = "".join(hashlib.sha256(value).hexdigest() + "  " + prefix + "/" + name + "\n" for name, value in payloads.items())
if scenario == "checksum-only":
    checksum = ""
payloads["SHA256SUMS"] = checksum.encode()
for name, value in payloads.items():
    (tree / name).parent.mkdir(parents=True, exist_ok=True)
    (tree / name).write_bytes(value)
inventory = root / "verified-files.json"
inventory.write_text(json.dumps({name: hashlib.sha256(value).hexdigest() for name, value in payloads.items()}))
plan = root / "publish-plan.json"
hook = root / "custom-hook-ran"
mutation = root / "release-mutation-ran"
expected = scenario in ("space-name", "unicode-name", "right-bracket-name", "dash-name", "normal-name", "relative-stage")
parser_demo = None
uploaded_names = []
checksum_bytes_match = False
copy_output_empty = True
post_hook_failure = scenario in ("checksum-mutated-after-hook", "checksum-slot-replaced-after-hook", "checksum-symlink-after-hook")
if scenario == "distinct-hash-label":
    demo = root / "cli-parser-demo"
    demo.mkdir()
    (demo / "x").write_bytes(b"base")
    (demo / "x#label").write_bytes(b"distinct")
    argument = str(demo / "x#label")
    index = argument.find("#")
    parsed_path = argument[:index] if index > 0 else argument
    parser_demo = {"literalBytes": (demo / "x#label").read_bytes().decode(), "firstHashBytes": Path(parsed_path).read_bytes().decode(), "label": argument[index + 1:]}
if not shell:
    stage_arg = "stage" if scenario == "relative-stage" else str(stage)
    args = [str(tree), str(inventory), prefix, prefix + "/RELEASE_NOTES.md", stage_arg, str(plan)]
    planned = subprocess.run([sys.executable, "-I", "-S", program, "plan", *args], cwd=root, capture_output=True)
    copied = None
    if planned.returncode == 0:
        hook.write_bytes(b"unit-hook-boundary")
        if scenario == "checksum-mutated-after-hook":
            (tree / "SHA256SUMS").write_bytes(b"hook changed checksum bytes")
        elif scenario == "checksum-slot-replaced-after-hook":
            slot = stage / "SHA256SUMS"
            if slot.exists():
                slot.rename(stage / "original-checksum-slot")
            slot.write_bytes(b"replacement destination")
        elif scenario == "checksum-symlink-after-hook":
            original = tree / "SHA256SUMS"
            original.rename(tree / "original-checksum")
            original.symlink_to("original-checksum")
        copied = subprocess.run([sys.executable, "-I", "-S", program, "copy", *args], cwd=root, capture_output=True)
        if copied.returncode == 0:
            mutation.write_bytes(b"unit-release-boundary")
    success = planned.returncode == 0 and copied is not None and copied.returncode == 0
    if success:
        destinations = [Path(os.fsdecode(value)) for value in copied.stdout.split(b"\0") if value]
        uploaded_names = [destination.name for destination in destinations]
        expected_names = {Path(name).name for name in names} | {"RELEASE_NOTES.md", "SHA256SUMS"}
        checksum_bytes_match = "SHA256SUMS" in uploaded_names and (stage / "SHA256SUMS").read_bytes() == payloads["SHA256SUMS"]
        success = len(destinations) == len(expected_names) and set(uploaded_names) == expected_names and all(destination.is_absolute() and destination.read_bytes() == payloads[destination.name] for destination in destinations)
    copy_output_empty = copied is None or copied.stdout == b""
    stderr = planned.stderr.decode() + (copied.stderr.decode() if copied else "")
else:
    fixture = root / "adapters"
    fixture.mkdir()
    (fixture / "python3").symlink_to(sys.executable)
    run_name = {"hash-parent": "run#label", "star-parent": "run*", "question-parent": "run?", "class-parent": "run[0]", "backslash-parent": "run\\escape"}.get(scenario, "run")
    run_temp = root / run_name
    run_temp.mkdir()
    evidence = {"schema_version": 1, "repo": "fake/repo", "version": "v1.2.3", "channel": "stable", "target_sha": "a" * 40, "preflight_run_id": "101", "run_attempt": "1"}
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for name, value in payloads.items():
            package.writestr(name, value)
        package.writestr("release-evidence.json", json.dumps(evidence))
    raw = data.getvalue()
    (root / "package.zip").write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()
    (root / "metadata.json").write_text(json.dumps({"id": 202, "name": "release-package", "expired": False, "digest": "sha256:" + sha, "workflow_run": {"id": 101, "repository_id": 42, "head_sha": "b" * 40}}))
    (root / "attempt.json").write_text(json.dumps({"id": 101, "run_attempt": 1, "repository": {"id": 42, "full_name": "fake/repo"}, "status": "completed", "conclusion": "success", "head_sha": "b" * 40}))
    gh = fixture / "gh"
    gh.write_text("#!" + sys.executable + "\n" + '''from pathlib import Path
import json,os,sys
r=Path(os.environ["OWNED_FIXTURE_ROOT"])
a=sys.argv[1:]
with (r/"gh-calls.jsonl").open("a") as log: log.write(json.dumps(a)+"\\n")
if a==["api","repos/fake/repo/actions/artifacts/202"]: sys.stdout.buffer.write((r/"metadata.json").read_bytes())
elif a==["api","repos/fake/repo/actions/artifacts/202/zip"]: sys.stdout.buffer.write((r/"package.zip").read_bytes())
elif a==["api","repos/fake/repo/actions/runs/101/attempts/1"]: sys.stdout.buffer.write((r/"attempt.json").read_bytes())
elif a[:2]==["run","download"]:
    target=Path(a[a.index("--dir")+1]); target.resolve().relative_to(r.resolve())
    (target/"validation-evidence.json").write_text(json.dumps({"repo":"fake/repo","target_sha":"a"*40,"validation_run_id":"303"}))
elif a[:2]==["run","view"]: print("success")
else:
    (r/"release-mutation-ran").write_bytes(b"unexpected-route")
    sys.exit(73)
''')
    gh.chmod(0o700)
    git = fixture / "git"
    git.write_text('#!/bin/sh\n[ "$1" = rev-parse ] || exit 73\nprintf "%s\\n" '+"a"*40+'\n')
    git.chmod(0o700)
    publish = root / "publish-hook.sh"
    publish.write_text('#!/bin/sh\nprintf called > "$OWNED_FIXTURE_ROOT/custom-hook-ran"\n')
    publish.chmod(0o700)
    environment = dict(os.environ, PATH=str(fixture) + ":" + os.environ["PATH"], OWNED_FIXTURE_ROOT=str(root), RUNNER_TEMP=str(run_temp), GITHUB_REPOSITORY="fake/repo", GITHUB_REPOSITORY_ID="42", PREFLIGHT_RUN_ID="101", PREFLIGHT_ARTIFACT_ID="202", PREFLIGHT_ARTIFACT_SHA256=sha, REQUIRE_IMMUTABLE_PREFLIGHT="true", VALIDATION_RUN_ID="303", TAG="v1.2.3", CHANNEL="stable", RELEASE_ISSUE="27", REQUIRE_RELEASE_ISSUE="true", REQUIRE_SIGNED_TAG="false", REQUIRE_POSTPUBLISH_VERIFICATION="false", CREATE_GITHUB_RELEASE="true", UPDATE_MAJOR_TAG="false", UPDATE_MINOR_TAG="false", TAG_PREFIX="v", ARTIFACT_DIR=prefix, RELEASE_NOTES_FILE=prefix+"/RELEASE_NOTES.md", PUBLISH_SCRIPT=str(publish), POSTPUBLISH_SCRIPT=str(root/"no-post-hook"))
    completed = subprocess.run(["bash", shell[0]], cwd=root, env=environment, capture_output=True)
    success = completed.returncode == 0
    stderr = completed.stderr.decode()
    calls = [json.loads(line) for line in (root/"gh-calls.jsonl").read_text().splitlines()]
    if any(call and call[0]=="release" for call in calls): mutation.write_bytes(b"unexpected-release-command")
report = {"scenario": scenario, "expectedSuccess": expected, "success": success, "hookRan": hook.exists(), "releaseMutationRan": mutation.exists(), "stderr": stderr, "parserDemo": parser_demo, "uploadedNames": uploaded_names, "checksumBytesMatch": checksum_bytes_match, "copyOutputEmpty": copy_output_empty, "failurePhase": "copy" if post_hook_failure else "plan"}
if post_hook_failure:
    detail = {"checksum-mutated-after-hook": "Consumed bytes differ from approved ZIP member.", "checksum-slot-replaced-after-hook": "Reserved staging slot changed."}.get(scenario, "")
    report["passed"] = not success and hook.exists() and not mutation.exists() and copy_output_empty and bool(stderr) and detail in stderr
elif not expected:
    detail = {"checksum-only": "No approved release assets were selected.", "checksum-flat-collision": "Duplicate flat release asset name."}.get(scenario, "unsupported CLI label/glob syntax")
    report["passed"] = not success and not hook.exists() and not mutation.exists() and detail in stderr
else:
    report["passed"] = success
print(json.dumps(report))
sys.exit(0 if report["passed"] else 1)
