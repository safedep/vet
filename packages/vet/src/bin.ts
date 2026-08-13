#!/usr/bin/env node
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";

const require = createRequire(import.meta.url);

function pkgNameForHost(): string {
  const platform = process.platform; // linux | darwin | win32
  const arch = process.arch;         // x64 | arm64
  return `@safedep/vet-${platform}-${arch}`;
}

function findBinaryPath(pkgName: string): string {
  const pkgJsonPath = require.resolve(`${pkgName}/package.json`);
  const pkgRoot = dirname(pkgJsonPath);
  const exe = process.platform === "win32" ? "vet.exe" : "vet";
  const p = join(pkgRoot, "bin", exe);
  if (!existsSync(p)) {
    throw new Error(
      `Binary not found at ${p}. The platform package "${pkgName}" is installed but does not contain bin/${exe}.`
    );
  }
  return p;
}

function main() {
  const pkgName = pkgNameForHost();
  let binPath: string;
  try {
    binPath = findBinaryPath(pkgName);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(
      [
        "Failed to locate the platform binary.",
        `Host: ${process.platform}/${process.arch}`,
        `Expected platform package: ${pkgName}`,
        msg,
        "",
        "Common causes:",
        "- optionalDependencies were omitted during install",
        "- this platform/arch is not published yet",
        "- the platform package was published without the binary in bin/",
      ].join("\n")
    );
    process.exit(1);
  }

  const child = spawn(binPath, process.argv.slice(2), { stdio: "inherit" });

  child.on("exit", (code: number | null, signal: string | null) => {
    if (signal) {
      process.kill(process.pid, signal as NodeJS.Signals);
      return;
    }
    process.exit(code ?? 1);
  });
  child.on("error", (error: Error) => {
    console.error(`Failed to spawn the binary: ${error}`);
    process.exit(1);
  });
}

main();
