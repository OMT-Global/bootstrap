import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, chmodSync, rmSync, realpathSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { runInNewContext } from "node:vm";
import { expect, it } from "vitest";
import { CONTAINER_SETUP } from "../src/isolation/setup.js";

it.each(["observe", "reject-active-policy"] as const)("replays the declared native Git hook invocation: %s", (policy) => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), "bootstrap-hook-observation-")));
  const repo = path.join(root, "repo"), home = path.join(root, "home"); mkdirSync(repo); mkdirSync(home);
  const author = { name: "Planned Author", email: "author@example.invalid", date: "1767225600 +0530" };
  const committer = { name: "Planned Committer", email: "committer@example.invalid", date: "1767225660 -0600" };
  // Native, replay, and nested Git use the profile's same fixed tool search path.
  const minimal: NodeJS.ProcessEnv = { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_CONFIG_GLOBAL: "/dev/null", GIT_ATTR_NOSYSTEM: "1", GIT_OPTIONAL_LOCKS: "0", GIT_EDITOR: ":" };
  const planned = { ...minimal };
  for (const [kind, identity] of Object.entries({ author, committer })) for (const [field, value] of Object.entries(identity)) {
    planned[`GIT_${kind.toUpperCase()}_${field.toUpperCase()}`] = (field === "date" ? "@" : "") + value;
  }
  const git = (...args: string[]) => execFileSync("git", args, { cwd: repo, env: planned, encoding: "utf8" });
  try {
    git("init", "-q", "--template="); git("config", "user.name", committer.name); git("config", "user.email", committer.email);
    git("config", "commit.gpgsign", "false"); git("config", "core.hooksPath", "/disabled-hooks"); git("config", "core.fsmonitor", "false");
    writeFileSync(path.join(repo, "source"), "fabricated public base\n"); git("add", "source");
    const base = execFileSync("git", ["commit-tree", git("write-tree").trim()], { cwd: repo, env: planned, encoding: "utf8", input: "test: synthetic base\n" }).trim();
    const branch = "codex/hook-observation"; git("symbolic-ref", "HEAD", `refs/heads/${branch}`); git("update-ref", "HEAD", base);
    const hook = path.join(repo, ".githooks/pre-commit"), observation = path.join(root, "hook-context.json"); mkdirSync(path.dirname(hook));
    const fixedPolicy = policy === "reject-active-policy" ? `if(record.hooksPath==='/disabled-hooks')process.exit(0);if(record.environment.GIT_DIR!=='.git')process.exit(21);if(read('show',':source')==='fabricated public prepared')process.exit(23);` : "";
    writeFileSync(hook, `#!${process.execPath}\nconst fs=require('node:fs'),cp=require('node:child_process');\nconst read=(...args)=>cp.execFileSync('git',args,{encoding:'utf8'}).trim();\nconst record={args:process.argv.slice(2),cwd:process.cwd(),environment:Object.fromEntries(Object.entries(process.env).filter(([key])=>key.startsWith('GIT_'))),hooksPath:read('config','--get','core.hooksPath'),branch:read('symbolic-ref','--short','HEAD'),base:read('rev-parse','HEAD'),index:read('ls-files','--stage'),staged:read('diff','--cached','--name-only'),message:fs.readFileSync('.git/COMMIT_EDITMSG','utf8'),author:read('var','GIT_AUTHOR_IDENT'),committer:read('var','GIT_COMMITTER_IDENT')};\nfs.writeFileSync(${JSON.stringify(observation)},JSON.stringify(record));${fixedPolicy}\n`);
    chmodSync(hook, 0o755); writeFileSync(path.join(repo, "source"), "fabricated public prepared\n");
    writeFileSync(path.join(repo, "package.json"), '{"name":"hook-observation","version":"1.0.0"}');
    writeFileSync(path.join(repo, "package-lock.json"), '{"lockfileVersion":3,"packages":{"":{"name":"hook-observation","version":"1.0.0"}}}');
    git("add", "source", "package.json", "package-lock.json", ".githooks/pre-commit"); const preparedTree = git("write-tree").trim();
    const commitMessage = "test: observe declared hook context\n\nSigned-off-by: Planned Author <author@example.invalid>\n";
    // The frozen message is a declared prepared artifact before pre-commit, not an ambient Git timing guarantee.
    writeFileSync(path.join(repo, ".git/COMMIT_EDITMSG"), commitMessage); writeFileSync(path.join(root, "message"), commitMessage);
    const nativeCommit = () => git("--git-dir=.git", "-c", "core.hooksPath=.githooks", "commit", "-q", `--file=${path.join(root, "message")}`);
    if (policy === "observe") nativeCommit(); else expect(nativeCommit).toThrow();
    const native = JSON.parse(readFileSync(observation, "utf8")); git("update-ref", "HEAD", base);
    writeFileSync(path.join(repo, ".git/COMMIT_EDITMSG"), commitMessage);
    const virtualProcess = { argv: ["node", "setup.cjs", "hook"], env: minimal, exitCode: 0 };
    const fsAdapter = {
      readFileSync: (name: string) => { expect(name).toBe("/input/manifest.json"); return JSON.stringify({ author, committer, branch, baseCommit: base, commitMessage, hook: ".githooks/pre-commit" }); },
      mkdirSync: () => undefined, writeFileSync: () => undefined,
      cpSync: (source: string, target: string) => { expect([source, target]).toEqual(["/pristine-cache", "/npm-cache"]); }
    };
    const cpAdapter = { execFileSync: (command: string, args: string[], options: Record<string, unknown>) => {
      // Only this fixed synthetic hook and real Git execute on the host; actual target execution stays in Docker.
      if (command === "npm") { expect(args).toEqual(["ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", "--engine-strict"]); return ""; }
      return execFileSync(command === "/repo/project/.githooks/pre-commit" ? hook : command, args,
        { ...options, cwd: repo, env: (options.env as NodeJS.ProcessEnv | undefined) ?? minimal } as Parameters<typeof execFileSync>[2]);
    } };
    runInNewContext(CONTAINER_SETUP, { require: (name: string) => name === "node:fs" ? fsAdapter : name === "node:child_process" ? cpAdapter : name === "node:path" ? path : {}, process: virtualProcess,
      console: { error: () => undefined }, TextDecoder, Buffer });
    expect(virtualProcess.exitCode).toBe(policy === "observe" ? 0 : 1);
    const replay = JSON.parse(readFileSync(observation, "utf8")); expect(replay).toEqual(native);
    expect(replay.environment).toMatchObject({ GIT_DIR: ".git", GIT_INDEX_FILE: ".git/index", GIT_PREFIX: "", GIT_EDITOR: ":" });
    expect(replay).toMatchObject({ args: [], cwd: repo, hooksPath: ".githooks", branch, base, message: commitMessage });
    expect(replay.staged.split("\n")).toEqual([".githooks/pre-commit", "package-lock.json", "package.json", "source"]);
    expect(git("write-tree").trim()).toBe(preparedTree);
    expect(replay.author).toBe(`${author.name} <${author.email}> ${author.date}`);
    expect(replay.committer).toBe(`${committer.name} <${committer.email}> ${committer.date}`);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

it.each(["missing", "version", "functional", "success"])("requires jq preflight before dependency/source work: %s", (result) => {
  const events: string[] = [];
  const virtualProcess = { argv: ["node", "setup.cjs", "prepare"], version: "v24.22.1", exitCode: 0 };
  const outputs: Record<string, string> = { bash: "GNU bash fixture\n", git: "git version fixture\n", python3: "Python 3 fixture\n", npm: "11.19.1\n" };
  const fsAdapter = {
    readFileSync: (name: string) => { expect(name).toBe("/input/manifest.json"); return "{}"; },
    mkdirSync: (name: string) => { events.push(`mkdir:${name}`); }, writeFileSync: () => undefined,
    copyFileSync: () => { events.push("dependency-copy"); throw new Error("Stop after the successful preflight."); }
  };
  const cpAdapter = { execFileSync: (command: string, args: string[], options: Record<string, unknown>) => {
    if (command !== "jq") { events.push(`version:${command}`); return outputs[command]; }
    if (args[0] === "--version") {
      events.push("jq-version"); if (result === "missing") throw new Error("No jq.");
      return result === "version" ? "unrelated tool\n" : "jq-1.6\n";
    }
    events.push("jq-functional"); expect(args).toEqual(["-ce", ".[] | select(.enabled) | .items | map(. + 1) == [2,3]"]);
    expect(options).toMatchObject({ cwd: "/input", encoding: "utf8", input: '[{"enabled":true,"items":[1,2]}]', maxBuffer: 1024 });
    return result === "functional" ? "false\n" : "true\n";
  } };
  runInNewContext(CONTAINER_SETUP, { require: (name: string) => name === "node:fs" ? fsAdapter : name === "node:child_process" ? cpAdapter : {},
    process: virtualProcess, console: { error: () => undefined }, Buffer });
  expect(virtualProcess.exitCode).toBe(1);
  expect(events).toContain("jq-version");
  expect(events.includes("jq-functional")).toBe(result === "functional" || result === "success");
  expect(events.includes("mkdir:/install")).toBe(result === "success");
  expect(events.includes("dependency-copy")).toBe(result === "success");
  if (result === "success") expect(events.indexOf("jq-functional")).toBeLessThan(events.indexOf("mkdir:/install"));
});
