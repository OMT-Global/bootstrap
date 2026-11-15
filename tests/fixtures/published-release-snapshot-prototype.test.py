import copy
import json
import pathlib
import subprocess
import sys
import unittest

source = pathlib.Path(__file__).parents[2].joinpath("src/published-release-snapshot.ts").read_text()
program = source.split("return String.raw`", 1)[1].rsplit("`;", 1)[0]
namespace = {}
exec(program, namespace)
collect = namespace["collect_published_release"]
SnapshotError = namespace["SnapshotError"]

COMMIT = "a" * 40
TAG_OBJECT = "b" * 40
DIGEST = "c" * 64
REQUEST = {"repository": "example/repo", "release_id": 42, "tag": "v1.2.3", "commit": COMMIT}

class Provider:
    def __init__(self):
        self.calls = []
        self.repos = {"full_name": "Example/repo"}
        self.release_pages = {None: {"items": [{"id": 42, "tag_name": "v1.2.3", "draft": False, "body": "notes\n", "prerelease": False}], "next": None}}
        self.asset_pages = {None: {"items": [{"id": 12, "name": "archive.tar.gz", "size": 5, "state": "uploaded", "digest": "sha256:" + DIGEST}], "next": None}}
        self.ref = {"type": "commit", "sha": COMMIT}
        self.objects = {}
        self.latest_result = {"release_id": 42}
        self.denied_at = None
        self.tag_reads = 0
        self.auth_calls = 0
    def repository(self, repo):
        self.calls.append(("repository", repo))
        return copy.deepcopy(self.repos)
    def releases(self, repo, cursor):
        self.calls.append(("releases", repo, cursor))
        return copy.deepcopy(self.release_pages[cursor])
    def assets(self, repo, release_id, cursor):
        self.calls.append(("assets", repo, release_id, cursor))
        return copy.deepcopy(self.asset_pages[cursor])
    def tag_ref(self, repo, tag):
        self.calls.append(("tag_ref", repo, tag))
        self.tag_reads += 1
        if self.denied_at == "moved" and self.tag_reads == 2:
            return {"type": "commit", "sha": "d" * 40}
        return copy.deepcopy(self.ref)
    def tag_object(self, repo, sha):
        self.calls.append(("tag_object", repo, sha))
        return copy.deepcopy(self.objects[sha])
    def latest(self, repo):
        self.calls.append(("latest", repo))
        return copy.deepcopy(self.latest_result)

def authorize(provider, repo):
    provider.auth_calls += 1
    if provider.denied_at == provider.auth_calls:
        raise ValueError("fake sensitive error")

class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.p = Provider()
        self.request = copy.deepcopy(REQUEST)
    def result(self):
        return collect(self.p, authorize, self.request)
    def rejected(self):
        with self.assertRaisesRegex(SnapshotError, "Release snapshot unavailable") as caught:
            self.result()
        self.assertNotIn("sensitive", str(caught.exception))
    def test_success_matches_comparator_contract(self):
        actual = self.result()
        self.assertEqual(actual, {"repository": "Example/repo", "release_id": 42, "tag": "v1.2.3", "commit": COMMIT,
          "notes": "notes\n", "prerelease": False, "latest": True, "draft": False,
          "assets": [{"id": 12, "name": "archive.tar.gz", "size": 5, "state": "uploaded", "sha256": DIGEST, "digest_source": "provider-sha256"}]})
        self.assertEqual(self.p.auth_calls, 2)
        self.assertEqual(self.p.tag_reads, 2)
        self.assertTrue(all(call[0] in {"repository", "releases", "assets", "tag_ref", "tag_object", "latest"} for call in self.p.calls))
    def test_output_executes_actual_frozen_comparator(self):
        actual = self.result()
        expected = {key: actual[key] for key in ("repository", "release_id", "tag", "commit", "notes", "prerelease", "latest")}
        expected["assets"] = [{"name": a["name"], "size": a["size"], "sha256": a["sha256"], "digest_source": "approved-bytes"} for a in actual["assets"]]
        comparator_source = pathlib.Path(__file__).parents[2].joinpath("src/published-release-verifier.ts").read_text()
        comparator = comparator_source.split("return String.raw`", 1)[1].rsplit("`;", 1)[0]
        result = subprocess.run([sys.executable, "-I", "-S", "-c", comparator], input=json.dumps({"schema_version": 1, "expected": expected, "actual": actual}), text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"eligible": True})
    def test_paginated_match_and_assets(self):
        selected = self.p.release_pages[None]["items"]
        self.p.release_pages = {None: {"items": [{"id": 41, "tag_name": "other", "draft": False, "body": "", "prerelease": False}], "next": "p2"}, "p2": {"items": selected, "next": None}}
        first = self.p.asset_pages[None]["items"]
        self.p.asset_pages = {None: {"items": first, "next": "p2"}, "p2": {"items": [{"id": 13, "name": "manifest", "size": 0, "state": "uploaded", "digest": "sha256:" + DIGEST}], "next": None}}
        self.assertEqual(len(self.result()["assets"]), 2)
    def test_absent_is_error_not_authorization_to_create(self):
        self.p.release_pages[None]["items"] = []
        self.rejected()
        self.assertNotIn("assets", [call[0] for call in self.p.calls])
    def test_denied_before_and_after_observation(self):
        for n in (1, 2):
            with self.subTest(n=n):
                self.p = Provider(); self.p.denied_at = n; self.rejected()
    def test_noncallable_or_non_none_authorization_fails(self):
        for auth in (None, lambda provider, repo: False, lambda provider, repo: True):
            with self.subTest(auth=auth):
                with self.assertRaises(SnapshotError): collect(self.p, auth, self.request)
    def test_invalid_request_identity_rejected_before_authorization_or_provider_calls(self):
        values = [("repository", "./.."), ("repository", "-owner/repo"), ("repository", "owner/.."), ("tag", "a..b"), ("tag", "a b"), ("tag", "a@{b"), ("tag", "a\nb"), ("tag", "a/.hidden"), ("tag", "a.lock"), ("tag", "-tag")]
        for field, value in values:
            with self.subTest(field=field, value=value):
                self.p = Provider(); self.request = copy.deepcopy(REQUEST); self.request[field] = value
                self.rejected(); self.assertEqual(self.p.calls, []); self.assertEqual(self.p.auth_calls, 0)
    def test_valid_slash_unicode_tag_and_enterprise_owner(self):
        self.request.update(repository="managed_user/repo", tag="v/β")
        self.p.repos["full_name"] = "managed_user/repo"
        self.p.release_pages[None]["items"][0]["tag_name"] = "v/β"
        self.assertEqual(self.result()["tag"], "v/β")
    def test_repository_mismatch_or_extra_shape_rejected(self):
        for repo in ({"full_name": "other/repo"}, {"full_name": "example/repo", "permissions": {"push": True}}, None):
            with self.subTest(repo=repo):
                self.p = Provider(); self.p.repos = repo; self.rejected()
    def test_matching_draft_wrong_id_and_duplicate_release_fail(self):
        for mutator in (lambda r: r.update(draft=True), lambda r: r.update(id=99), lambda r: r.update(id=True)):
            with self.subTest(mutator=mutator):
                self.p = Provider(); mutator(self.p.release_pages[None]["items"][0]); self.rejected()
        self.p = Provider(); self.p.release_pages[None]["items"].append(copy.deepcopy(self.p.release_pages[None]["items"][0])); self.rejected()
        self.p = Provider(); duplicate = copy.deepcopy(self.p.release_pages[None]["items"][0]); duplicate["id"] = 43; self.p.release_pages[None]["items"].append(duplicate); self.rejected()
    def test_page_shape_cursor_loop_and_truncation(self):
        cases = [None, {}, {"items": [], "next": "next"}, {"items": [], "next": 12}, {"items": [1] * 101, "next": None}]
        for page in cases:
            with self.subTest(page=page):
                self.p = Provider(); self.p.release_pages[None] = page; self.rejected()
        self.p = Provider(); item = self.p.release_pages[None]["items"][0]; self.p.release_pages = {None: {"items": [item], "next": "x"}, "x": {"items": [{**item, "id": 43, "tag_name": "other"}], "next": "x"}}; self.rejected()
    def test_page_bound(self):
        self.p.release_pages = {None if i == 0 else str(i): {"items": [{"id": i + 100, "tag_name": str(i), "draft": False, "body": "", "prerelease": False}], "next": str(i + 1)} for i in range(20)}
        self.rejected()
    def test_item_bound_and_nul_cursor(self):
        self.p.release_pages = {None if i == 0 else str(i): {"items": [{"id": i * 100 + j + 100, "tag_name": str(i * 100 + j), "draft": False, "body": None, "prerelease": False} for j in range(100)], "next": str(i + 1)} for i in range(11)}
        self.rejected()
        self.p = Provider(); self.p.release_pages[None]["next"] = "bad\0cursor"; self.rejected()
    def test_invalid_asset_fields_and_duplicates(self):
        mutations = [lambda a: a.update(id=True), lambda a: a.update(size=True), lambda a: a.update(size=-1), lambda a: a.update(state="new"), lambda a: a.update(digest=None), lambda a: a.update(digest="sha1:"+DIGEST), lambda a: a.update(digest="sha256:"+DIGEST.upper()), lambda a: a.update(name="../x")]
        for f in mutations:
            with self.subTest(f=f):
                self.p = Provider(); f(self.p.asset_pages[None]["items"][0]); self.rejected()
        self.p = Provider(); self.p.asset_pages[None]["items"].append(copy.deepcopy(self.p.asset_pages[None]["items"][0])); self.rejected()
        self.p = Provider(); duplicate = copy.deepcopy(self.p.asset_pages[None]["items"][0]); duplicate["id"] = 13; self.p.asset_pages[None]["items"].append(duplicate); self.rejected()
        self.p = Provider(); self.p.asset_pages[None]["items"] = []; self.rejected()
    def test_annotated_tag_and_cycle(self):
        self.p.ref = {"type": "tag", "sha": TAG_OBJECT}; self.p.objects[TAG_OBJECT] = {"type": "commit", "sha": COMMIT}
        self.assertEqual(self.result()["commit"], COMMIT)
        self.p.objects[TAG_OBJECT] = {"type": "tag", "sha": TAG_OBJECT}; self.rejected()
    def test_annotated_tag_depth_bound(self):
        shas = [format(i, "040x") for i in range(1, 12)]
        self.p.ref = {"type": "tag", "sha": shas[0]}
        self.p.objects = {sha: {"type": "tag", "sha": shas[i + 1]} for i, sha in enumerate(shas[:-1])}
        self.p.objects[shas[-1]] = {"type": "commit", "sha": COMMIT}
        self.rejected()
    def test_tag_mismatch_or_change_before_return_fails(self):
        self.p.ref = {"type": "commit", "sha": "d" * 40}; self.rejected()
        self.p = Provider(); self.p.denied_at = "moved"; self.rejected()
    def test_latest_identity_must_be_explicit(self):
        self.p.release_pages[None]["items"].append({"id": 23, "tag_name": "v2", "draft": False, "body": None, "prerelease": False})
        self.p.latest_result = {"release_id": 23}; self.assertFalse(self.result()["latest"])
        self.p = Provider(); self.p.latest_result = {"release_id": None}; self.assertFalse(self.result()["latest"])
        for value in ({}, {"release_id": True}, None):
            with self.subTest(value=value):
                self.p = Provider(); self.p.latest_result = value; self.rejected()
        self.p = Provider(); self.p.latest_result = {"release_id": 23}; self.rejected()
        self.p = Provider(); self.p.release_pages[None]["items"].append({"id": 23, "tag_name": "other", "draft": True, "body": None, "prerelease": False}); self.p.latest_result = {"release_id": 23}; self.rejected()
    def test_unrelated_null_body_is_allowed_selected_null_body_rejected(self):
        self.p.release_pages[None]["items"].append({"id": 23, "tag_name": "other", "draft": True, "body": None, "prerelease": False})
        self.assertEqual(self.result()["release_id"], 42)
        self.p = Provider(); self.p.release_pages[None]["items"][0]["body"] = None; self.rejected()
    def test_provider_errors_are_sanitized(self):
        self.p.release_pages = {}
        self.rejected()

if __name__ == "__main__":
    unittest.main(verbosity=2)
