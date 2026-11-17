import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import { type ApprovedReleasePackage, approvedReleasePackageMetadata } from "./release-approved-package.js";
import { readGitHubExactTag } from "./github-approval-reader.js";
import { verifyExistingGitHubRelease } from "./github-existing-release.js";
import { nextReleasePage, releaseJson, releaseObject } from "./github-release-transport.js";

const zero = "0".repeat(40);
const sha = z.string().regex(/^[0-9a-f]{40}$/);
const id = z.string().regex(/^[1-9][0-9]{0,15}$/);
const recordSchema = z.object({ schema_version: z.literal(1), action: z.literal("promote_release_aliases"), authorized_by: id,
  authorized_at: z.string().datetime(), expires_at: z.string().datetime(), repository: z.literal("OMT-Global/bootstrap"), repository_id: id,
  app_id: z.number().int().positive().safe(), installation_id: z.number().int().positive().safe(),
  tag: z.string(), commit: sha, tag_object: sha, approval_sha256: z.string().regex(/^[0-9a-f]{64}$/), release_id: id,
  operation_run_id: id, operation_attempt: id, operation_workflow_commit: sha,
  updates: z.array(z.object({ name: z.string(), beforeOid: sha, afterOid: sha }).strict()).min(1).max(2) }).strict();

export type AliasAuthorization = {
  json: string;
  sha256: string;
  authorizerId: string;
  appId: number;
  installationId: number;
  operationRunId: string;
  operationAttempt: string;
  operationWorkflowCommit: string;
};

type Version = readonly [bigint, bigint, bigint];

function version(tag: string): Version | undefined {
  if (tag.length > 1024) throw new Error();
  const match = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.exec(tag);
  return match ? [BigInt(match[1]!), BigInt(match[2]!), BigInt(match[3]!)] : undefined;
}

function compare(a: Version, b: Version) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i]! < b[i]! ? -1 : 1;
  }
  return 0;
}
const order = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;

const refsQuery = `query AliasInventory($id: ID!, $cursor: String) { node(id: $id) { ... on Repository { id nameWithOwner isPrivate
 refs(refPrefix: "refs/tags/", first: 100, after: $cursor) { totalCount pageInfo { endCursor hasNextPage }
  nodes { name prefix target { __typename oid ... on Tag { target { __typename oid } } } } } } } }`;
const mutation = `mutation PromoteAliases($input: UpdateRefsInput!) { updateRefs(input: $input) { clientMutationId } }`;

/** Explicit operation authority comes from reviewed protected deployment config,
 * not package diagnostics or an arbitrary environment hash. This is one expected-
 * before transaction, not a lock over release/tag inventory or an automatic retry. */

export async function promoteApprovedReleaseAliases(input: {
  package: ApprovedReleasePackage;
  token: string;
  authorization: AliasAuthorization;
  major: boolean;
  minor: boolean;
  revalidate: () => Promise<void>;
  fetchImpl?: typeof fetch;
}) {
  try {
    const { package: packageFact, token, major, minor, revalidate } = input;
    const auth = { ...input.authorization };
    const fetcher = input.fetchImpl ?? fetch;
    const expected = approvedReleasePackageMetadata(packageFact);
    const target = version(expected.tag);
    if (!target || expected.prerelease || expected.repository !== "OMT-Global/bootstrap" || typeof major !== "boolean" || typeof minor !== "boolean" ||
      (!major && !minor) || !/^[\x21-\x7e]{1,4096}$/.test(token) || typeof auth.json !== "string" || Buffer.byteLength(auth.json) > 8192 ||
      createHash("sha256").update(auth.json).digest("hex") !== auth.sha256)
      throw new Error();
    const authority = recordSchema.parse(JSON.parse(auth.json));
    const start = Date.parse(authority.authorized_at), expires = Date.parse(authority.expires_at);
    if (expires <= start || expires - start > 600000 || authority.authorized_by !== auth.authorizerId || authority.app_id !== auth.appId ||
      authority.installation_id !== auth.installationId || authority.repository !== expected.repository || authority.repository_id !== expected.repositoryId ||
      authority.tag !== expected.tag || authority.commit !== expected.commit || authority.approval_sha256 !== expected.approvalSha256 ||
      authority.operation_run_id !== auth.operationRunId || authority.operation_attempt !== auth.operationAttempt || authority.operation_workflow_commit !== auth.operationWorkflowCommit ||
      authority.updates.some((u) => u.afterOid !== expected.commit || u.afterOid === zero) || new Set(authority.updates.map((u) => u.name)).size !== authority.updates.length)
      throw new Error();
    const valid = () => {
      if (Date.now() < start || Date.now() >= expires) throw new Error();
      approvedReleasePackageMetadata(packageFact);
    };
    const base = `https://api.github.com/repos/${expected.repository}`;
    const headers = { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" };
    async function get(url: string) {
      const response = await fetcher(url, { method: "GET", headers, redirect: "manual", signal: AbortSignal.timeout(30000) });
      return { value: await releaseJson(response, url, 200), link: response.headers.get("link") };
    }
    async function graphql(query: string, variables: unknown, write = false) {
      const url = "https://api.github.com/graphql";
      const options = { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, redirect: "manual" as const,
        signal: AbortSignal.timeout(30000), body: JSON.stringify({ query, variables }) };
      if (write)
        valid(); // After every await and body preparation, immediately before the only mutation.
      const value = releaseObject(await releaseJson(await fetcher(url, options), url, 200));
      if (value.errors !== undefined)
        throw new Error();
      return releaseObject(value.data);
    }
    async function gate() {
      valid();
      if (await revalidate() !== undefined)
        throw new Error();
      const tag = await readGitHubExactTag({ repository: expected.repository, repositoryId: expected.repositoryId, tag: expected.tag,
        expectedCommit: expected.commit, requireSigned: true, token, fetchImpl: fetcher });
      if (tag.objectId !== authority.tag_object)
        throw new Error();
      valid();
    }
    async function verifyRelease() {
      const observed = await verifyExistingGitHubRelease({ package: packageFact, token, revalidate: gate, fetchImpl: fetcher });
      if (observed.releaseId !== authority.release_id)
        throw new Error();
      valid();
    }
    async function releases() {
      const items: Record<string, unknown>[] = [];
      const ids = new Set<number>();
      for (let page = 1; page <= 20; page++) {
        const url = `${base}/releases?per_page=100&page=${page}`;
        const result = await get(url);
        if (!Array.isArray(result.value) || result.value.length > 100)
          throw new Error();
        for (const value of result.value) {
          const r = releaseObject(value);
          if (typeof r.id !== "number" || !Number.isSafeInteger(r.id) || r.id < 1 || ids.has(r.id) || typeof r.tag_name !== "string" ||
            !r.tag_name || r.tag_name.length > 1024 || typeof r.draft !== "boolean" || typeof r.prerelease !== "boolean")
            throw new Error();
          ids.add(r.id);
          items.push(r);
          if (items.length > 1000)
            throw new Error();
        }
        const next = nextReleasePage(result.link, url, page);
        if (next && !result.value.length)
          throw new Error();
        if (!next && result.value.length < 100)
          return items;
      }
      throw new Error();
    }
    async function observe() {
      const repo = releaseObject((await get(base)).value);
      if (String(repo.id) !== expected.repositoryId || repo.full_name !== expected.repository || repo.private !== false ||
        releaseObject(repo.permissions).push !== true || typeof repo.node_id !== "string" || !repo.node_id || repo.node_id.length > 1024)
        throw new Error();
      const refs = new Map<string, {
        oid: string;
        commit?: string;
      }>();
      const cursors = new Set<string>();
      let cursor: string | null = null, total: number | undefined, complete = false;
      for (let page = 0; page < 20; page++) {
        const node = releaseObject((await graphql(refsQuery, { id: repo.node_id, cursor })).node);
        if (node.id !== repo.node_id || node.nameWithOwner !== expected.repository || node.isPrivate !== false)
          throw new Error();
        const connection = releaseObject(node.refs), info = releaseObject(connection.pageInfo);
        if (typeof connection.totalCount !== "number" || !Number.isSafeInteger(connection.totalCount) || connection.totalCount < 0 || connection.totalCount > 1000 ||
          (total !== undefined && total !== connection.totalCount) || !Array.isArray(connection.nodes) || connection.nodes.length > 100 || typeof info.hasNextPage !== "boolean")
          throw new Error();
        total = connection.totalCount;
        for (const value of connection.nodes) {
          const ref = releaseObject(value), object = releaseObject(ref.target);
          if (typeof ref.name !== "string" || !ref.name || ref.name.length > 1024 || ref.name.includes("\0") || ref.prefix !== "refs/tags/" || refs.has(ref.name))
            throw new Error();
          const oid = sha.parse(object.oid);
          if (oid === zero)
            throw new Error();
          let commit: string | undefined;
          if (object.__typename === "Commit")
            commit = oid;
          else if (object.__typename === "Tag") {
            const nested = releaseObject(object.target);
            if (nested.__typename === "Commit")
              commit = sha.parse(nested.oid);
          }
          refs.set(ref.name, { oid, ...(commit ? { commit } : {}) });
        }
        if (!info.hasNextPage) {
          if (refs.size !== total)
            throw new Error();
          complete = true;
          break;
        }
        if (!connection.nodes.length || typeof info.endCursor !== "string" || !info.endCursor || info.endCursor.length > 1024 || cursors.has(info.endCursor))
          throw new Error();
        cursor = info.endCursor;
        cursors.add(cursor);
      }
      if (!complete || refs.get(expected.tag)?.oid !== authority.tag_object || refs.get(expected.tag)?.commit !== expected.commit)
        throw new Error();
      return { nodeId: repo.node_id, refs, releases: await releases() };
    }
    type Inventory = Awaited<ReturnType<typeof observe>>;
    function plan(inventory: Inventory, after = false) {
      const stable = [...inventory.refs].flatMap(([tag, object]) => { const v = version(tag); return v ? [{ tag, version: v, ...object }] : []; });
      const desired = [{ enabled: minor, name: `v${target![0]}.${target![1]}`, minor: true }, { enabled: major, name: `v${target![0]}`, minor: false }];
      const updates: Array<{
        name: string;
        beforeOid: string;
        afterOid: string;
        baseline: string | null;
      }> = [];
      for (const alias of desired.filter((d) => d.enabled)) {
        const compatible = (v: Version) => v[0] === target![0] && (!alias.minor || v[1] === target![1]);
        for (const release of inventory.releases) {
          const v = version(String(release.tag_name));
          if (!release.draft && !release.prerelease && v && compatible(v) && compare(v, target!) >= 0 && !inventory.refs.has(String(release.tag_name)))
            throw new Error();
        }
        const candidates = stable.filter((s) => compatible(s.version));
        if (candidates.some((s) => compare(s.version, target!) > 0))
          continue;
        const current = inventory.refs.get(alias.name);
        let baseline: string | null = null;
        if (current) {
          if (!current.commit)
            throw new Error();
          const matching = candidates.filter((s) => s.commit === current.commit).sort((a, b) => compare(b.version, a.version));
          if (!matching.length || compare(matching[0]!.version, target!) > 0)
            throw new Error();
          baseline = matching[0]!.tag;
        }
        updates.push({ name: `refs/tags/${alias.name}`, beforeOid: current?.oid ?? zero, afterOid: expected.commit, baseline });
      }
      updates.sort((a, b) => order(a.name, b.name));
      const authorized = [...authority.updates].sort((a, b) => order(a.name, b.name));
      if (!updates.length || updates.length !== authorized.length || updates.some((u, i) => u.name !== authorized[i]!.name ||
        u.beforeOid !== (after ? authorized[i]!.afterOid : authorized[i]!.beforeOid)))
        throw new Error();
      return updates;
    }
    await verifyRelease();
    const first = await observe();
    const selected = plan(first);
    await verifyRelease();
    const second = await observe();
    const confirmed = plan(second);
    if (first.nodeId !== second.nodeId || JSON.stringify(selected) !== JSON.stringify(confirmed))
      throw new Error();
    await gate();
    const changed = confirmed.filter((u) => u.beforeOid !== u.afterOid).map((u) => u.name);
    if (changed.length) {
      const clientMutationId = randomUUID();
      const result = await graphql(mutation, { input: { repositoryId: second.nodeId, clientMutationId,
          refUpdates: confirmed.map(({ name, beforeOid, afterOid }) => ({ name, beforeOid, afterOid, force: true })) } }, true);
      if (releaseObject(result.updateRefs).clientMutationId !== clientMutationId)
        throw new Error();
    }
    await verifyRelease();
    const final = await observe();
    plan(final, true);
    await gate();
    if (final.nodeId !== second.nodeId)
      throw new Error();
    return Object.freeze({ kind: changed.length ? "promoted-aliases" as const : "verified-unchanged-aliases" as const,
      repository: expected.repository, releaseId: authority.release_id, tag: expected.tag, commit: expected.commit,
      aliases: Object.freeze(confirmed.map((u) => u.name)), changed: Object.freeze(changed) });
  }
  catch {
    throw new Error("Alias promotion stopped; manually reconcile any uncertain ref transaction. No retry, fallback or rollback was attempted.");
  }
}
