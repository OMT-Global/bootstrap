import { createHash } from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";

const token = "fabricated-read-capability-0123456789";
const manifest = "version: 1\nproject:\n  name: service\n  owner: acme\n  visibility: public\n  defaultBranch: main\narchetype:\n  kind: generic-empty\nrepo:\n  class: cli\n";
const body = Buffer.from(manifest);
const sha1 = (value) => createHash("sha1").update(value).digest("hex");
const head = sha1("fixture-head");
const tree = sha1("fixture-tree");
const blob = createHash("sha1").update(`blob ${body.length}\0`).update(body).digest("hex");
const repository = { id: 1, name: "service", full_name: "acme/service", owner: { login: "acme", id: 7, type: "Organization" }, private: false, visibility: "public", default_branch: "main", fork: false, archived: false, disabled: false };

globalThis.fetch = async (input, init = {}) => {
  const url = new URL(String(input));
  if (url.origin !== "https://api.github.com" || init.method !== "GET" || init.redirect !== "error") throw new Error("Unexpected request boundary.");
  const listing = url.pathname === "/orgs/acme/repos";
  if (listing ? init.headers.Authorization !== undefined : init.headers.Authorization !== `Bearer ${token}`) throw new Error("Unexpected request authority.");
  if (process.env.DISCOVERY_FIXTURE_MODE === "object-404" && url.pathname.includes("/git/ref/")) {
    const denied = new Response(JSON.stringify({ message: `fixture ${token}` }), { status: 404, headers: { "Content-Type": "application/json" } });
    Object.defineProperty(denied, "url", { value: url.href });
    return denied;
  }
  let value;
  if (listing) value = [repository];
  else if (url.pathname === "/repos/acme/service") value = repository;
  else if (url.pathname === "/repos/acme/service/git/ref/heads/main") value = { ref: "refs/heads/main", object: { type: "commit", sha: head } };
  else if (url.pathname === `/repos/acme/service/git/commits/${head}`) value = { sha: head, tree: { sha: tree } };
  else if (url.pathname === `/repos/acme/service/git/trees/${tree}`) value = { sha: tree, truncated: false, tree: [{ path: "project.bootstrap.yaml", type: "blob", mode: "100644", sha: blob, size: body.length }] };
  else if (url.pathname === `/repos/acme/service/git/blobs/${blob}`) value = { sha: blob, size: body.length, encoding: "base64", content: body.toString("base64") };
  else throw new Error("Unexpected request path.");
  const response = new Response(JSON.stringify(value), { status: 200, headers: { "Content-Type": "application/json" } });
  Object.defineProperty(response, "url", { value: url.href });
  return response;
};

const cli = path.resolve("src/cli.ts");
process.argv = [process.execPath, cli, ...process.argv.slice(2)];
await import(pathToFileURL(cli).href);
