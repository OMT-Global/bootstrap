import { spawn } from "node:child_process";

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface CommandOptions {
  cwd?: string;
  input?: string;
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

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (exitCode) => {
      resolve({
        stdout,
        stderr,
        exitCode: exitCode ?? 0
      });
    });

    if (options.input) {
      child.stdin.write(options.input);
    }
    child.stdin.end();
  });
