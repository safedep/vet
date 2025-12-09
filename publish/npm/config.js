// Configuration for npm binary wrapper

const ORG_NAME = "@safedep";
const PACKAGE_NAME = "vet";
const BINARY_NAME = "vet";

// GitHub repository information for releases
const REPO_OWNER = "safedep";
const REPO_NAME = "vet";

// GitHub releases base URL (constructed from repo info)
const GITHUB_RELEASES_BASE = `https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download`;

// Platform-specific binary filename patterns (GoReleaser format)
const BINARY_PATTERNS = {
  "darwin-x64": `${BINARY_NAME}_Darwin_x86_64.tar.gz`,
  "darwin-arm64": `${BINARY_NAME}_Darwin_arm64.tar.gz`,
  "linux-x64": `${BINARY_NAME}_Linux_x86_64.tar.gz`,
  "linux-arm64": `${BINARY_NAME}_Linux_arm64.tar.gz`,
  "win32-x64": `${BINARY_NAME}_Windows_x86_64.zip`,
};

module.exports = {
  ORG_NAME,
  PACKAGE_NAME,
  BINARY_NAME,
  REPO_OWNER,
  REPO_NAME,
  GITHUB_RELEASES_BASE,
  BINARY_PATTERNS,
};
