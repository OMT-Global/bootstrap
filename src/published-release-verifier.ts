/** A self-contained, inactive comparator for embedding in a generated workflow. */
export function publishedReleaseVerifierScript(): string {
  return String.raw`import json
import os
import re
import sys

MAX_INPUT = 4 * 1024 * 1024
MAX_NOTES = 1024 * 1024
MAX_ASSETS = 1000
MAX_INTEGER = 2 ** 53 - 1

class Invalid(Exception):
    pass

def require(condition):
    if not condition:
        raise Invalid()

def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result

def reject_constant(_value):
    raise Invalid()

def parse_integer(value):
    require(len(value.lstrip("-")) <= 16)
    return int(value)

def fields(value, names):
    require(type(value) is dict and set(value) == set(names))

def bounded_text(value, limit):
    require(type(value) is str and "\0" not in value)
    require(len(value.encode("utf-8")) <= limit)
    return value

def positive_id(value):
    require(type(value) is int and 0 < value <= MAX_INTEGER)

def valid_tag(value):
    require(value and value != "@" and not value.startswith(("-", "/")) and not value.endswith(("/", ".")))
    require(".." not in value and "//" not in value and "@{" not in value)
    require(not any(ord(ch) < 32 or ord(ch) == 127 or ch in " ~^:?*[\\" for ch in value))
    require(all(not part.startswith(".") and not part.endswith(".lock") for part in value.split("/")))

def metadata(value, actual):
    names = ("repository", "release_id", "tag", "commit", "notes", "prerelease", "latest", "assets")
    fields(value, names + (("draft",) if actual else ()))
    repo = bounded_text(value["repository"], 201)
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) is not None)
    owner, name = repo.split("/")
    require(len(owner) <= 100 and len(name) <= 100 and set(owner) != {"."} and set(name) != {"."})
    require(re.fullmatch(r"[A-Za-z0-9_.](?:[A-Za-z0-9_.-]*[A-Za-z0-9_.])?", owner) is not None)
    positive_id(value["release_id"])
    tag = bounded_text(value["tag"], 1024)
    valid_tag(tag)
    require(type(value["commit"]) is str and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value["commit"]) is not None)
    bounded_text(value["notes"], MAX_NOTES)
    require(type(value["prerelease"]) is bool and type(value["latest"]) is bool)
    if actual:
        require(value["draft"] is False)

def asset_records(records, actual):
    require(type(records) is list and 0 < len(records) <= MAX_ASSETS)
    result = {}
    ids = set()
    for record in records:
        keys = ("name", "size", "sha256", "digest_source")
        fields(record, keys + (("id", "state") if actual else ()))
        name = bounded_text(record["name"], 1024)
        require(name not in ("", ".", "..") and "/" not in name and "\\" not in name and name not in result)
        require(type(record["size"]) is int and 0 <= record["size"] <= MAX_INTEGER)
        require(type(record["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is not None)
        if actual:
            positive_id(record["id"])
            require(record["id"] not in ids and record["state"] == "uploaded")
            ids.add(record["id"])
            require(record["digest_source"] in ("provider-sha256", "authenticated-stream"))
        else:
            require(record["digest_source"] == "approved-bytes")
        result[name] = (record["size"], record["sha256"])
    return result

try:
    data = sys.stdin.buffer.read(MAX_INPUT + 1)
    require(len(data) <= MAX_INPUT)
    envelope = json.loads(data.decode("utf-8"), object_pairs_hook=object_pairs, parse_constant=reject_constant, parse_float=reject_constant, parse_int=parse_integer)
    fields(envelope, ("schema_version", "expected", "actual"))
    require(type(envelope["schema_version"]) is int and envelope["schema_version"] == 1)
    expected, actual = envelope["expected"], envelope["actual"]
    metadata(expected, False)
    metadata(actual, True)
    require(expected["repository"].lower() == actual["repository"].lower())
    for key in ("release_id", "tag", "commit", "notes", "prerelease", "latest"):
        require(expected[key] == actual[key])
    require(asset_records(expected["assets"], False) == asset_records(actual["assets"], True))
    sys.stdout.write('{"eligible":true}\n')
except (Invalid, ValueError, UnicodeError, RecursionError, TypeError):
    sys.stderr.write("Published release verification failed.\n")
    sys.exit(1)`;
}
