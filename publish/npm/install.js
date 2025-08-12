#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const os = require("os");
const https = require("https");
const crypto = require("crypto");
const { execSync } = require("child_process");
const {
  BINARY_NAME,
  REPO_OWNER,
  REPO_NAME,
  GITHUB_RELEASES_BASE,
  BINARY_PATTERNS,
} = require("./config");

// Read version from package.json with strict validation
function getValidatedVersion() {
  try {
    const packageJson = JSON.parse(
      fs.readFileSync(path.join(__dirname, "package.json"), "utf8"),
    );

    const version = packageJson.version;

    // Strict validation: must be valid semver (x.y.z)
    if (!/^\d+\.\d+\.\d+$/.test(version)) {
      throw new Error(`Invalid version format: ${version}`);
    }

    return `v${version}`;
  } catch (error) {
    throw new Error(`Failed to read valid version: ${error.message}`);
  }
}

const RELEASE_VERSION = getValidatedVersion();
const BASE_URL = `${GITHUB_RELEASES_BASE}/${RELEASE_VERSION}`;

// Platform-specific binary URLs (constructed from config)
const BINARY_URLS = {};
Object.keys(BINARY_PATTERNS).forEach((platform) => {
  BINARY_URLS[platform] = `${BASE_URL}/${BINARY_PATTERNS[platform]}`;
});

const CHECKSUMS_URL = `${BASE_URL}/checksums.txt`;

function getPlatformKey() {
  const platform = process.platform;
  const arch = process.arch;
  return `${platform}-${arch}`;
}

function downloadFile(url, dest, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    if (maxRedirects < 0) {
      reject(new Error("Too many redirects"));
      return;
    }

    const file = fs.createWriteStream(dest);

    https
      .get(url, (response) => {
        if (response.statusCode === 302 || response.statusCode === 301) {
          file.close();
          fs.unlink(dest, () => {});
          return downloadFile(response.headers.location, dest, maxRedirects - 1)
            .then(resolve)
            .catch(reject);
        }

        if (response.statusCode !== 200) {
          file.close();
          fs.unlink(dest, () => {});
          reject(new Error(`Download failed: ${response.statusCode}`));
          return;
        }

        response.pipe(file);

        file.on("finish", () => {
          file.close();
          resolve();
        });

        file.on("error", (err) => {
          fs.unlink(dest, () => {});
          reject(err);
        });
      })
      .on("error", reject);
  });
}

function calculateChecksum(filePath) {
  const fileBuffer = fs.readFileSync(filePath);
  const hashSum = crypto.createHash("sha256");
  hashSum.update(fileBuffer);
  return hashSum.digest("hex");
}

function validateChecksum(filePath, expectedChecksum) {
  const actualChecksum = calculateChecksum(filePath);
  return actualChecksum === expectedChecksum;
}

function extractArchive(archivePath, extractDir) {
  const isZip = archivePath.endsWith(".zip");

  if (isZip) {
    execSync(`unzip -o "${archivePath}" -d "${extractDir}"`, { stdio: "pipe" });
  } else {
    execSync(`tar -xzf "${archivePath}" -C "${extractDir}"`, { stdio: "pipe" });
  }
}

async function install() {
  let tempWorkspace;

  try {
    console.log(`📦 Installing ${BINARY_NAME} binary...`);

    // Get platform-specific URL
    const platformKey = getPlatformKey();
    const binaryUrl = BINARY_URLS[platformKey];

    if (!binaryUrl) {
      throw new Error(`Unsupported platform: ${platformKey}`);
    }

    console.log(`🔍 Platform: ${platformKey}`);
    console.log(`📡 Version: ${RELEASE_VERSION}`);

    // Create directories
    const binDir = path.join(__dirname, "bin");
    tempWorkspace = fs.mkdtempSync(
      path.join(os.tmpdir(), `${BINARY_NAME}-install-`),
    );

    fs.mkdirSync(binDir, { recursive: true });

    // Download binary archive
    const archiveFilename = path.basename(binaryUrl);
    const archivePath = path.join(tempWorkspace, archiveFilename);

    console.log(`⬇️  Downloading binary...`);
    await downloadFile(binaryUrl, archivePath);

    // Download checksums
    const checksumsPath = path.join(tempWorkspace, "checksums.txt");
    console.log(`⬇️  Downloading checksums...`);
    await downloadFile(CHECKSUMS_URL, checksumsPath);

    // Parse checksums file
    const checksumsContent = fs.readFileSync(checksumsPath, "utf8");
    const checksumLines = checksumsContent.split("\n");

    let expectedChecksum = null;
    for (const line of checksumLines) {
      if (line.includes(archiveFilename)) {
        expectedChecksum = line.split(/\s+/)[0];
        break;
      }
    }

    if (!expectedChecksum) {
      throw new Error(`Checksum not found for ${archiveFilename}`);
    }

    // Validate checksum
    console.log(`🔐 Validating checksum...`);
    if (!validateChecksum(archivePath, expectedChecksum)) {
      throw new Error(
        "Checksum validation failed - binary may be corrupted or tampered",
      );
    }

    console.log(`✅ Checksum validated`);

    // Extract archive
    console.log(`📂 Extracting binary...`);
    extractArchive(archivePath, tempWorkspace);

    // Find and move binary
    const binaryName =
      process.platform === "win32" ? `${BINARY_NAME}.exe` : BINARY_NAME;
    const extractedBinaryPath = path.join(tempWorkspace, binaryName);
    const finalBinaryPath = path.join(binDir, binaryName);

    if (!fs.existsSync(extractedBinaryPath)) {
      throw new Error(
        `Binary not found at expected location: ${extractedBinaryPath}`,
      );
    }

    // Move binary to final location (handle cross-device links)
    try {
      fs.renameSync(extractedBinaryPath, finalBinaryPath);
    } catch (error) {
      if (error.code === "EXDEV") {
        // Cross-device link not permitted, copy and delete instead
        fs.copyFileSync(extractedBinaryPath, finalBinaryPath);
        fs.unlinkSync(extractedBinaryPath);
      } else {
        throw error;
      }
    }

    // Make executable on Unix systems
    if (process.platform !== "win32") {
      fs.chmodSync(finalBinaryPath, "755");
    }

    // Clean up
    fs.rmSync(tempWorkspace, { recursive: true, force: true });

    console.log("✅ Vet binary installed successfully!");
  } catch (error) {
    console.error("❌ Installation failed:", error.message);

    // Clean up on failure
    try {
      if (tempWorkspace && fs.existsSync(tempWorkspace)) {
        fs.rmSync(tempWorkspace, { recursive: true, force: true });
      }
    } catch (cleanupError) {
      console.warn("⚠️  Failed to clean up:", cleanupError.message);
    }

    process.exit(1);
  }
}

// Run installation
install();
