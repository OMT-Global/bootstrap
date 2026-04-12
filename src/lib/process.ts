import { spawn } from "node:child_process";

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface CommandOptions {
  cwd?: string;
  input?: string;
  timeoutMs?: number;
}

export type CommandRunner = (
  command: string,
  args?: string[],
  options?: CommandOptions
) => Promise<CommandResult>;

export const execRunner: CommandRunner = (command, args = [], options = {}) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      stdio: "pipe",
      env: process.env
    });

    let stdout = "";
    let stderr = "";
    let settled = false;

    const finish = (result: CommandResult | Error) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (result instanceof Error) {
        reject(result);
      } else {
        resolve(result);
      }
    };

    let timer: ReturnType<typeof setTimeout> | undefined;
    if (options.timeoutMs !== undefined) {
      timer = setTimeout(() => {
        child.kill("SIGTERM");
        finish(new Error(`Command timed out after ${options.timeoutMs}ms: ${command}`));
      }, options.timeoutMs);
    }

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (err) => finish(err));
    child.on("close", (exitCode) => {
      finish({ stdout, stderr, exitCode: exitCode ?? 0 });
    });

    if (options.input) {
      child.stdin.write(options.input);
    }
    child.stdin.end();
  });
