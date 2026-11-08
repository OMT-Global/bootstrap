import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, chmodSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { runInNewContext } from "node:vm";
import { expect, it } from "vitest";
import { CONTAINER_SETUP } from "../src/isolation/setup.js";

it("replays the declared no-editor all-staged hook context observed from real Git", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "bootstrap-hook-observation-"));
  const repo = path.join(root, "repo"), home = path.join(root, "home"); mkdirSync(repo); mkdirSync(home);
  const author = { name: "Planned Author", email: "author@example.invalid", date: "1767225600 +0530" };
  const committer = { name: "Planned Committer", email: "committer@example.invalid", date: "1767225660 -0600" };
  const minimal: NodeJS.ProcessEnv = { PATH: "/usr/bin:/bin:/usr/local/bin", HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_EDITOR: ":" };
  const planned = { ...minimal };
  for (const [kind, identity] of Object.entries({ author, committer })) for (const [field, value] of Object.entries(identity)) {
    planned[`GIT_${kind.toUpperCase()}_${field.toUpperCase()}`] = (field === "date" ? "@" : "") + value;
  }
  const git = (...args: string[]) => execFileSync("/usr/bin/git", args, { cwd: repo, env: planned, encoding: "utf8" });
  try {
    git("init", "-q", "--template="); git("config", "user.name", committer.name); git("config", "user.email", committer.email);
    git("config", "commit.gpgsign", "false");
    const hook = path.join(repo, ".git/hooks/pre-commit"); mkdirSync(path.dirname(hook), { recursive: true });
    const keys = ["GIT_INDEX_FILE", "GIT_PREFIX", "GIT_EDITOR", "GIT_EXEC_PATH", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_AUTHOR_DATE", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "GIT_COMMITTER_DATE"];
    writeFileSync(hook, `#!${process.execPath}\nconst fs=require('node:fs'),cp=require('node:child_process');\nconst keys=${JSON.stringify(keys)};\nfs.writeFileSync('hook-context.json',JSON.stringify({args:process.argv.slice(2),environment:Object.fromEntries(keys.map(key=>[key,process.env[key]])),author:cp.execFileSync('git',['var','GIT_AUTHOR_IDENT'],{encoding:'utf8'}).trim(),committer:cp.execFileSync('git',['var','GIT_COMMITTER_IDENT'],{encoding:'utf8'}).trim()}));\n`);
    chmodSync(hook, 0o755); writeFileSync(path.join(repo, "source"), "fabricated public data\n");
    writeFileSync(path.join(repo, "package.json"), '{"name":"hook-observation","version":"1.0.0"}');
    writeFileSync(path.join(repo, "package-lock.json"), '{"lockfileVersion":3,"packages":{"":{"name":"hook-observation","version":"1.0.0"}}}');
    git("add", "source", "package.json", "package-lock.json");
    git("commit", "-qm", "test: observe real hook environment");
    const native = JSON.parse(readFileSync(path.join(repo, "hook-context.json"), "utf8"));
    expect(native.environment.GIT_INDEX_FILE).toBe(".git/index"); expect(native.environment.GIT_PREFIX).toBe("");
    const virtualProcess = { argv: ["node", "setup.cjs", "hook"], env: minimal, exitCode: 0 };
    const fsAdapter = {
      readFileSync: (name: string) => { expect(name).toBe("/input/manifest.json"); return JSON.stringify({ author, committer, hook: ".githooks/pre-commit" }); },
      mkdirSync: () => undefined, writeFileSync: () => undefined,
      cpSync: (source: string, target: string) => { expect([source, target]).toEqual(["/pristine-cache", "/npm-cache"]); }
    };
    const cpAdapter = { execFileSync: (command: string, args: string[], options: Record<string, unknown>) => {
      // Installation is exercised by the Docker suite; this observation uses only real Git and the fixed test hook.
      if (command === "npm") { expect(args).toEqual(["ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", "--engine-strict"]); return ""; }
      return execFileSync(command === "/repo/project/.githooks/pre-commit" ? hook : command, args,
        { ...options, cwd: repo, env: (options.env as NodeJS.ProcessEnv | undefined) ?? minimal } as Parameters<typeof execFileSync>[2]);
    } };
    runInNewContext(CONTAINER_SETUP, { require: (name: string) => name === "node:fs" ? fsAdapter : name === "node:child_process" ? cpAdapter : name === "node:path" ? path : {}, process: virtualProcess, console, TextDecoder, Buffer });
    expect(virtualProcess.exitCode).toBe(0);
    const replay = JSON.parse(readFileSync(path.join(repo, "hook-context.json"), "utf8"));
    expect(replay).toEqual(native);
    expect(replay.author).toBe(`${author.name} <${author.email}> ${author.date}`);
    expect(replay.committer).toBe(`${committer.name} <${committer.email}> ${committer.date}`);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
