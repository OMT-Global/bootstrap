import { describe, expect, it, vi } from "vitest";
import { withScopedInstallationToken } from "../src/github-installation-token.js";

const appJwt = "fake.header.signature";
const token = "fabricated-test-token";
const input = { appId: 10, installationId: 20, repositoryId: 30, repository: "acme/release-fixture", appJwt, purpose: "release" as const };
const scopeUrl = "https://api.github.com/installation/repositories?per_page=100&page=1";
type Data = Record<string, unknown>;
function fixture(edit?: (value: Data) => void, options: {
  appId?: number; responseStatus?: number; raw?: string; redirected?: boolean;
  scopeStatus?: number; scopeRaw?: string; scopeLink?: string; scopeRedirected?: boolean;
  afterApp?: () => void; beforeScope?: () => void;
} = {}) {
  const calls: { url: string; init: RequestInit }[] = [];
  const now = new Date(Date.now() + 1800_000).toISOString().replace(/\.\d{3}Z$/, "Z");
  const payload: Data = { token, expires_at: now, permissions: { contents: "write", actions: "read", pull_requests: "read", metadata: "read" }, repository_selection: "selected", repositories: [{ id: 30 }] };
  const scope: Data = { total_count: 1, repositories: [{ id: 30, full_name: input.repository, private: false }] };
  edit?.(payload);
  const fetchImpl = async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const target = String(url);
    calls.push({ url: target, init: init ?? {} });
    const isApp = target === "https://api.github.com/app";
    const isScope = target === scopeUrl;
    if (!isApp && !isScope && target !== "https://api.github.com/app/installations/20/access_tokens") throw new Error("Unexpected fixture URL");
    if (isApp) options.afterApp?.();
    if (isScope) options.beforeScope?.();
    const body = isApp ? JSON.stringify({ id: options.appId ?? 10 }) : isScope ? options.scopeRaw ?? JSON.stringify(scope) : options.raw ?? JSON.stringify(payload);
    const response = new Response(body, { status: isApp ? 200 : isScope ? options.scopeStatus ?? 200 : options.responseStatus ?? 201,
      ...(isScope && options.scopeLink !== undefined ? { headers: { link: options.scopeLink } } : {}) });
    Object.defineProperty(response, "url", { value: options.redirected || (isScope && options.scopeRedirected) ? "https://evil.example/" : target });
    return response;
  };
  return { calls, payload, scope, options, fetchImpl: fetchImpl as typeof fetch };
}

describe("GitHub installation token issuance prototype", () => {
  it("rejects a release token missing required artifact and review read grants", async () => {
    const h = fixture((value) => { value.permissions = { contents: "write", metadata: "read" }; });
    let invoked = false;
    await expect(withScopedInstallationToken({ ...input, fetchImpl: h.fetchImpl }, async () => { invoked = true; }))
      .rejects.toThrow("Scoped GitHub installation token unavailable.");
    expect(invoked).toBe(false);
  });
  it("rejects private repository visibility before the fleet consumer", async () => {
    const h = fixture((value) => { value.permissions = { contents: "write", pull_requests: "write", metadata: "read" }; });
    let invoked = false;
    const fetchImpl = async (url: string | URL | Request, init?: RequestInit) => {
      if (String(url).startsWith("https://api.github.com/installation/repositories")) {
        const response = new Response(JSON.stringify({ total_count: 1, repositories: [{ id: 30, full_name: "acme/release-fixture", private: true }] }));
        Object.defineProperty(response, "url", { value: String(url) });
        return response;
      }
      return h.fetchImpl(url, init);
    };
    await expect(withScopedInstallationToken({ ...input, purpose: "fleet-pr", fetchImpl }, async () => { invoked = true; }))
      .rejects.toThrow("Scoped GitHub installation token unavailable.");
    expect(invoked).toBe(false);
  });
  it("requests one repository and only release permissions before calling the trusted consumer", async () => {
    const h = fixture();
    let seen = 0;
    await withScopedInstallationToken({ ...input, fetchImpl: h.fetchImpl }, async (value, expires) => {
      expect(value).toBe(token);
      expect(expires.getTime()).toBeGreaterThan(Date.now());
      seen++;
    });
    expect(seen).toBe(1);
    expect(h.calls.map(({ url }) => url)).toEqual(["https://api.github.com/app", "https://api.github.com/app/installations/20/access_tokens", scopeUrl]);
    expect(JSON.parse(String(h.calls[1].init.body))).toEqual({ repository_ids: [30], permissions: { contents: "write", actions: "read", pull_requests: "read" } });
    expect(h.calls[2].init.method).toBe("GET");
    expect((h.calls[2].init.headers as Record<string, string>).Authorization).toBe(`Bearer ${token}`);
    expect(h.calls.every(({ init }) => init.redirect === "manual")).toBe(true);
  });
  it("requests PR write only for the fleet PR publisher", async () => {
    const h = fixture((v) => { v.permissions = { contents: "write", pull_requests: "write", metadata: "read" }; });
    await withScopedInstallationToken({ ...input, purpose: "fleet-pr", fetchImpl: h.fetchImpl }, async () => {});
    expect(JSON.parse(String(h.calls[1].init.body)).permissions).toEqual({ contents: "write", pull_requests: "write" });
  });
  it("rejects a different authenticated app before issuing a token", async () => {
    const h = fixture(undefined, { appId: 11 });
    await expect(withScopedInstallationToken({ ...input, fetchImpl: h.fetchImpl }, async () => {})).rejects.toThrow("Scoped GitHub installation token unavailable.");
    expect(h.calls).toHaveLength(1);
  });
  it.each([
    ["another repository", { total_count: 1, repositories: [{ id: 31, full_name: input.repository, private: false }] }],
    ["renamed repository", { total_count: 1, repositories: [{ id: 30, full_name: "acme/other", private: false }] }],
    ["private repository", { total_count: 1, repositories: [{ id: 30, full_name: input.repository, private: true }] }],
    ["missing visibility", { total_count: 1, repositories: [{ id: 30, full_name: input.repository }] }],
    ["multiple repository authority", { total_count: 2, repositories: [{ id: 30, full_name: input.repository, private: false }] }],
    ["missing repository", { total_count: 1, repositories: [] }],
    ["boolean count", { total_count: true, repositories: [{ id: 30, full_name: input.repository, private: false }] }],
    ["missing count", { repositories: [{ id: 30, full_name: input.repository, private: false }] }]
  ])("rejects %s in authenticated token visibility before invoking the consumer", async (_label, value) => {
    const h = fixture(undefined, { scopeRaw: JSON.stringify(value) });
    let invoked = false;
    await expect(withScopedInstallationToken({ ...input, fetchImpl: h.fetchImpl }, async () => { invoked = true; }))
      .rejects.toThrow("Scoped GitHub installation token unavailable.");
    expect(invoked).toBe(false);
    expect(h.calls.map((call) => call.url)).toEqual(["https://api.github.com/app", "https://api.github.com/app/installations/20/access_tokens", scopeUrl]);
  });
  it.each([
    { scopeStatus: 401 }, { scopeStatus: 403 }, { scopeStatus: 404 }, { scopeRedirected: true },
    { scopeLink: `<${scopeUrl.replace("page=1", "page=2")}>; rel="next"` },
    { scopeRaw: '{"total_count":1,"total_count":1,"repositories":[]}' },
    { scopeRaw: JSON.stringify({ total_count: 1, repositories: [{ id: 30, full_name: input.repository, private: false }], padding: "x".repeat(1024 * 1024) }) }
  ])("rejects incomplete or unavailable repository visibility %#", async (options) => {
    const h = fixture(undefined, options);
    let invoked = false;
    await expect(withScopedInstallationToken({ ...input, fetchImpl: h.fetchImpl }, async () => { invoked = true; }))
      .rejects.toThrow("Scoped GitHub installation token unavailable.");
    expect(invoked).toBe(false);
    expect(h.calls).toHaveLength(3);
  });
  it("rechecks the same scoped token and rejects revocation without issuing another token", async () => {
    const h = fixture();
    await withScopedInstallationToken({ ...input, fetchImpl: h.fetchImpl }, async (_token, _expires, assertRepositoryAccess) => {
      await assertRepositoryAccess();
      h.options.scopeStatus = 401;
      await expect(assertRepositoryAccess()).rejects.toThrow("Scoped GitHub installation token unavailable.");
    });
    expect(h.calls.filter(({ init }) => init.method === "POST")).toHaveLength(1);
    const checks = h.calls.filter(({ url }) => url === scopeUrl);
    expect(checks).toHaveLength(3);
    expect(checks.every(({ init }) => (init.headers as Record<string, string>).Authorization === `Bearer ${token}`)).toBe(true);
  });
  it("rejects changed repository visibility on a later boundary", async () => {
    const h = fixture();
    await withScopedInstallationToken({ ...input, fetchImpl: h.fetchImpl }, async (_token, _expires, assertRepositoryAccess) => {
      h.scope.repositories = [];
      await expect(assertRepositoryAccess()).rejects.toThrow("Scoped GitHub installation token unavailable.");
    });
    expect(h.calls).toHaveLength(4);
  });
  it("keeps a retained repository check usable after consumer completion until GitHub revocation", async () => {
    const h = fixture();
    let retainedCheck: (() => Promise<void>) | undefined;
    await withScopedInstallationToken({ ...input, fetchImpl: h.fetchImpl }, async (_token, _expires, check) => {
      retainedCheck = check;
    });
    expect(retainedCheck).toBeTypeOf("function");
    await expect(retainedCheck!()).resolves.toBeUndefined();
    h.options.scopeStatus = 401;
    await expect(retainedCheck!()).rejects.toThrow("Scoped GitHub installation token unavailable.");
    expect(h.calls.filter(({ url }) => url === scopeUrl)).toHaveLength(3);
    expect(h.calls.filter(({ init }) => init.method === "POST")).toHaveLength(1);
    expect(h.calls.some(({ init }) => init.method === "DELETE")).toBe(false);
  });
  it("retains its issuance expiry when the consumer mutates the exposed Date", async () => {
    const h = fixture();
    await withScopedInstallationToken({ ...input, fetchImpl: h.fetchImpl }, async (_token, expires, assertRepositoryAccess) => {
      const expiredAt = expires.getTime() + 1;
      expires.setTime(expiredAt + 86_400_000);
      const clock = vi.spyOn(Date, "now").mockReturnValue(expiredAt);
      try { await expect(assertRepositoryAccess()).rejects.toThrow("Scoped GitHub installation token unavailable."); }
      finally { clock.mockRestore(); }
    });
    expect(h.calls).toHaveLength(3);
  });
  it("rejects expiry during repository inspection before invoking the consumer", async () => {
    const h = fixture();
    const clock = vi.spyOn(Date, "now");
    h.options.beforeScope = () => { clock.mockReturnValue(Date.parse(String(h.payload.expires_at)) + 1); };
    let invoked = false;
    try {
      await expect(withScopedInstallationToken({ ...input, fetchImpl: h.fetchImpl }, async () => { invoked = true; }))
        .rejects.toThrow("Scoped GitHub installation token unavailable.");
    } finally { clock.mockRestore(); }
    expect(invoked).toBe(false);
    expect(h.calls).toHaveLength(3);
  });
  it("captures IDs, repository, purpose and transport before asynchronous observations", async () => {
    const h = fixture();
    const mutable: Parameters<typeof withScopedInstallationToken>[0] = { ...input, fetchImpl: h.fetchImpl };
    h.options.afterApp = () => {
      mutable.appId = 11;
      mutable.installationId = 21;
      mutable.repositoryId = 31;
      mutable.repository = "acme/other";
      mutable.purpose = "fleet-pr";
      mutable.appJwt = "another.fake.signature";
      mutable.fetchImpl = async () => { throw new Error("Must retain selected transport"); };
    };
    await withScopedInstallationToken(mutable, async (_token, _expires, assertRepositoryAccess) => { await assertRepositoryAccess(); });
    expect(h.calls).toHaveLength(4);
    expect(JSON.parse(String(h.calls[1].init.body))).toEqual({ repository_ids: [30], permissions: { contents: "write", actions: "read", pull_requests: "read" } });
    expect((h.calls[1].init.headers as Record<string, string>).Authorization).toBe(`Bearer ${appJwt}`);
  });
  it.each([
    ["other repo", (v: Data) => { v.repositories = [{ id: 31 }]; }],
    ["multiple repos", (v: Data) => { v.repositories = [{ id: 30 }, { id: 31 }]; }],
    ["implicit all repositories", (v: Data) => { v.repository_selection = "all"; }],
    ["no explicit repository list", (v: Data) => { delete v.repositories; }],
    ["read-only contents", (v: Data) => { v.permissions = { contents: "read" }; }],
    ["additional authority", (v: Data) => { v.permissions = { contents: "write", administration: "write" }; }],
    ["invalid token", (v: Data) => { v.token = "bad\ntoken"; }],
    ["expired", (v: Data) => { v.expires_at = "2000-01-01T00:00:00Z"; }],
    ["excessive lifetime", (v: Data) => { v.expires_at = "2100-01-01T00:00:00Z"; }]
  ])("rejects %s without invoking the consumer", async (_label, edit) => {
    const h = fixture(edit);
    let invoked = false;
    await expect(withScopedInstallationToken({ ...input, fetchImpl: h.fetchImpl }, async () => { invoked = true; })).rejects.toThrow();
    expect(invoked).toBe(false);
    expect(h.calls).toHaveLength(2);
  });
  it.each([
    { responseStatus: 403 }, { responseStatus: 422 }, { redirected: true },
    { raw: '{"token":"bad","token":"bad2"}' }
  ])("stops on an untrusted response %j without retrying issuance", async (options) => {
    const h = fixture(undefined, options);
    await expect(withScopedInstallationToken({ ...input, fetchImpl: h.fetchImpl }, async () => {})).rejects.toThrow();
    expect(h.calls.length).toBeLessThanOrEqual(2);
  });
  it("sanitizes consumer failures and does not invoke it again", async () => {
    const h = fixture();
    let calls = 0;
    await expect(withScopedInstallationToken({ ...input, fetchImpl: h.fetchImpl }, async () => { calls++; throw new Error(token); }))
      .rejects.toThrow("Scoped GitHub installation token unavailable.");
    expect(calls).toBe(1);
    expect(h.calls).toHaveLength(3);
  });
  it.each([
    { appJwt: "invalid" }, { repository: "acme/../other" }, { repository: "acme/.." },
    { repository: "acme/repo\n" }, { repositoryId: 0 }, { installationId: -1 }
  ])("rejects invalid identifiers and JWT before network access %#", async (invalid) => {
    const h = fixture();
    await expect(withScopedInstallationToken({ ...input, ...invalid, fetchImpl: h.fetchImpl }, async () => {})).rejects.toThrow();
    expect(h.calls).toHaveLength(0);
  });
});
