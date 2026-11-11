import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { parse } from "yaml";
import { expect, it } from "vitest";

const exec = promisify(execFile);

it("bundles the workflow checkout with its commit ancestry for isolated validation", async () => {
  const workflow = parse(await readFile(".github/workflows/fleet-isolation-validation.yml", "utf8"));
  const checkout = workflow.jobs["isolated-node-validation"].steps.find((step: { uses?: string }) => step.uses?.startsWith("actions/checkout@"));
  expect(checkout.with["fetch-depth"]).toBe(0);
  expect(checkout.with["persist-credentials"]).toBe(false);
  expect(checkout.with.ref).toBe("${{ github.sha }}");

  const root = await mkdtemp(path.join(os.tmpdir(), "isolation-workflow-history-"));
  const env = { PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0", LC_ALL: "C" };
  const git = async (cwd: string, ...args: string[]) => exec("git", args, { cwd, env });
  try {
    await git(root, "init", "-q", "source");
    const source = path.join(root, "source");
    await git(source, "config", "user.name", "Isolation Test");
    await git(source, "config", "user.email", "isolation-test@example.invalid");
    await git(source, "config", "commit.gpgsign", "false");
    await writeFile(path.join(source, "README"), "first\n");
    await git(source, "add", "README");
    await git(source, "commit", "-q", "-m", "first");
    await writeFile(path.join(source, "README"), "second\n");
    await git(source, "commit", "-q", "-am", "second");
    const head = (await git(source, "rev-parse", "HEAD")).stdout.trim();

    // A shallow clone builds a bundle, but a fresh isolated repo cannot fetch it.
    await git(root, "clone", "-q", "--no-local", "--depth", "1", source, "shallow");
    const shallow = path.join(root, "shallow");
    expect((await git(shallow, "rev-parse", "--is-shallow-repository")).stdout.trim()).toBe("true");
    const shallowBundle = path.join(root, "shallow.bundle");
    await git(shallow, "bundle", "create", shallowBundle, "HEAD");
    await git(root, "init", "-q", "shallow-target");
    await expect(git(path.join(root, "shallow-target"), "fetch", "-q", "--no-tags", "--no-write-fetch-head", shallowBundle, head))
      .rejects.toMatchObject({ stderr: expect.stringContaining("did not send all necessary objects") });

    // Match checkout's fetch-depth: 0 behavior and the isolated setup's fetch.
    await git(root, "clone", "-q", "--no-local", source, "full");
    const full = path.join(root, "full");
    expect((await git(full, "rev-parse", "--is-shallow-repository")).stdout.trim()).toBe("false");
    const fullBundle = path.join(root, "full.bundle");
    await git(full, "bundle", "create", fullBundle, "HEAD");
    await git(root, "init", "-q", "full-target");
    await git(path.join(root, "full-target"), "fetch", "-q", "--no-tags", "--no-write-fetch-head", fullBundle, head);
    expect((await git(path.join(root, "full-target"), "rev-parse", `${head}^{commit}`)).stdout.trim()).toBe(head);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}, 30000);
