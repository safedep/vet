#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { ORG_NAME, PACKAGE_NAME, BINARY_NAME } = require("../config");

const BINARY_NAME_WITH_EXT =
  process.platform === "win32" ? `${BINARY_NAME}.exe` : BINARY_NAME;
const BINARY_PATH = path.join(__dirname, BINARY_NAME_WITH_EXT);

function main() {
  // Check if binary exists
  if (!fs.existsSync(BINARY_PATH)) {
    console.error(`❌ ${BINARY_NAME_WITH_EXT} binary not found`);
    console.error(
      `Try reinstalling: npm install -g ${ORG_NAME}/${PACKAGE_NAME}`,
    );
    process.exit(1);
  }

  // Verify binary is executable
  try {
    fs.accessSync(BINARY_PATH, fs.constants.F_OK | fs.constants.X_OK);
  } catch (error) {
    console.error(`❌ ${BINARY_NAME_WITH_EXT} is not executable`);
    console.error(
      `Try reinstalling: npm install -g ${ORG_NAME}/${PACKAGE_NAME}`,
    );
    process.exit(1);
  }

  // Pass all arguments to the binary
  const args = process.argv.slice(2);

  // Spawn the binary with inherited stdio for proper terminal interaction
  const child = spawn(BINARY_PATH, args, {
    stdio: "inherit",
    windowsHide: false,
  });

  // Handle process termination
  child.on("error", (error) => {
    console.error(
      `❌ Failed to execute ${BINARY_NAME_WITH_EXT}: ${error.message}`,
    );
    console.error(
      `Try reinstalling: npm install -g ${ORG_NAME}/${PACKAGE_NAME}`,
    );
    process.exit(1);
  });

  // Exit with the same code as the child process
  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
    } else {
      process.exit(code || 0);
    }
  });

  // Handle termination signals
  process.on("SIGTERM", () => {
    child.kill("SIGTERM");
  });

  process.on("SIGINT", () => {
    child.kill("SIGINT");
  });
}

if (require.main === module) {
  main();
}

module.exports = { main };
