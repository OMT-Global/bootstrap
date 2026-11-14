/** Inactive snapshot collector. Runtime authorization is owned by its injected adapter. */
export function publishedReleaseSnapshotScript(): string {
  return String.raw`import re

MAX_PAGES = 20
MAX_ITEMS = 1000
MAX_TAG_DEPTH = 10
MAX_INTEGER = 2 ** 53 - 1
SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
DIGEST = re.compile(r"sha256:([0-9a-f]{64})\Z")

class SnapshotError(Exception):
    pass

def _require(condition):
    if not condition:
        raise SnapshotError("Release snapshot unavailable.")

def _id(value):
    _require(type(value) is int and 0 < value <= MAX_INTEGER)
    return value

def _text(value, limit):
    _require(type(value) is str and "\0" not in value and len(value.encode("utf-8")) <= limit)
    return value

def _sha(value):
    _require(type(value) is str and SHA.fullmatch(value) is not None)
    return value

def _repository(value):
    value = _text(value, 201)
    _require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value) is not None)
    owner, name = value.split("/")
    _require(len(owner) <= 100 and len(name) <= 100 and set(owner) != {"."} and set(name) != {"."})
    _require(re.fullmatch(r"[A-Za-z0-9_.](?:[A-Za-z0-9_.-]*[A-Za-z0-9_.])?", owner) is not None)
    return value

def _tag(value):
    value = _text(value, 1024)
    _require(value and value != "@" and not value.startswith(("-", "/")) and not value.endswith(("/", ".")))
    _require(".." not in value and "//" not in value and "@{" not in value)
    _require(not any(ord(ch) < 32 or ord(ch) == 127 or ch in " ~^:?*[\\" for ch in value))
    _require(all(not part.startswith(".") and not part.endswith(".lock") for part in value.split("/")))
    return value

def _pages(read_page):
    cursor = None
    seen = set()
    count = 0
    for _ in range(MAX_PAGES):
        page = read_page(cursor)
        _require(type(page) is dict and set(page) == {"items", "next"})
        items, next_cursor = page["items"], page["next"]
        _require(type(items) is list and len(items) <= 100)
        count += len(items)
        _require(count <= MAX_ITEMS)
        for item in items:
            yield item
        if next_cursor is None:
            return
        _text(next_cursor, 1024)
        _require(next_cursor and next_cursor not in seen and len(items) > 0)
        seen.add(next_cursor)
        cursor = next_cursor
    raise SnapshotError("Release snapshot unavailable.")

def _tag_commit(provider, repository, tag):
    ref = provider.tag_ref(repository, tag)
    seen = set()
    for _ in range(MAX_TAG_DEPTH + 1):
        _require(type(ref) is dict and set(ref) == {"type", "sha"})
        kind, sha = ref["type"], _sha(ref["sha"])
        if kind == "commit":
            return sha
        _require(kind == "tag" and sha not in seen and len(seen) < MAX_TAG_DEPTH)
        seen.add(sha)
        ref = provider.tag_object(repository, sha)
    raise SnapshotError("Release snapshot unavailable.")

def _collect_published_release(provider, authorize, request):
    """Collect facts only. authorize and provider are trusted code, not input data.

    authorize(provider, repository) must raise unless the same authenticated principal
    has complete release/draft and asset visibility, write authority, and a stable
    provider identity. No output flag or caller-controlled JSON can establish that.
    Provider methods must authenticate as the same principal, enforce raw response
    byte limits, reject duplicate JSON keys and partial/API errors, follow only
    same-provider pagination and bind each result to its request. They must supply
    authoritative latest/no-latest and stable, complete observations. A null cursor
    or a successful callback by itself does not establish completeness or authority.
    """
    _require(callable(authorize) and type(request) is dict and set(request) == {"repository", "release_id", "tag", "commit"})
    repository = _repository(request["repository"])
    _id(request["release_id"])
    tag, commit = _tag(request["tag"]), _sha(request["commit"])
    _require(authorize(provider, repository) is None)
    identity = provider.repository(repository)
    _require(type(identity) is dict and set(identity) == {"full_name"} and type(identity["full_name"]) is str and identity["full_name"].lower() == repository.lower())
    matches, release_ids = [], {}
    for release in _pages(lambda cursor: provider.releases(repository, cursor)):
        _require(type(release) is dict and set(release) == {"id", "tag_name", "draft", "body", "prerelease"})
        rid = _id(release["id"])
        _require(rid not in release_ids and type(release["draft"]) is bool and type(release["prerelease"]) is bool)
        release_ids[rid] = release["draft"]
        release_tag = _text(release["tag_name"], 1024)
        if release_tag == tag:
            _text(release["body"], 1024 * 1024)
            matches.append(release)
    _require(len(matches) == 1 and matches[0]["draft"] is False and matches[0]["id"] == request["release_id"])
    selected = matches[0]
    _require(_tag_commit(provider, repository, tag) == commit)
    assets, asset_ids, names = [], set(), set()
    for asset in _pages(lambda cursor: provider.assets(repository, request["release_id"], cursor)):
        _require(type(asset) is dict and set(asset) == {"id", "name", "size", "state", "digest"})
        aid = _id(asset["id"])
        name = _text(asset["name"], 1024)
        size = asset["size"]
        _require(name not in ("", ".", "..") and "/" not in name and "\\" not in name and name not in names and aid not in asset_ids)
        _require(type(size) is int and 0 <= size <= MAX_INTEGER and asset["state"] == "uploaded" and type(asset["digest"]) is str)
        digest = DIGEST.fullmatch(asset["digest"])
        _require(digest is not None)
        asset_ids.add(aid)
        names.add(name)
        assets.append({"id": aid, "name": name, "size": size, "state": "uploaded", "sha256": digest.group(1), "digest_source": "provider-sha256"})
    _require(len(assets) > 0)
    latest = provider.latest(repository)
    _require(type(latest) is dict and set(latest) == {"release_id"})
    if latest["release_id"] is not None:
        _id(latest["release_id"])
        _require(latest["release_id"] in release_ids and release_ids[latest["release_id"]] is False)
    _require(authorize(provider, repository) is None)
    _require(_tag_commit(provider, repository, tag) == commit)
    return {"repository": identity["full_name"], "release_id": selected["id"], "tag": tag, "commit": commit,
            "notes": selected["body"], "prerelease": selected["prerelease"], "latest": latest["release_id"] == selected["id"],
            "draft": False, "assets": assets}

def collect_published_release(provider, authorize, request):
    try:
        return _collect_published_release(provider, authorize, request)
    except Exception:
        raise SnapshotError("Release snapshot unavailable.") from None`;
}
