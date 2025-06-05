<div align="center">
  <h1>🔍 vet</h1>
  
  <p><strong>🚀 Enterprise grade open source software supply chain security</strong></p>
  
  <p>
    <a href="https://github.com/safedep/vet/releases"><strong>Download</strong></a> •
    <a href="#-quick-start"><strong>Quick Start</strong></a> •
    <a href="https://docs.safedep.io/"><strong>Documentation</strong></a> •
    <a href="#-community"><strong>Community</strong></a>
  </p>
</div>

<div align="center">

[![Go Report Card](https://goreportcard.com/badge/github.com/safedep/vet)](https://goreportcard.com/report/github.com/safedep/vet)
[![License](https://img.shields.io/github/license/safedep/vet)](https://github.com/safedep/vet/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/safedep/vet)](https://github.com/safedep/vet/releases)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/safedep/vet/badge)](https://api.securityscorecards.dev/projects/github.com/safedep/vet)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![CodeQL](https://github.com/safedep/vet/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/safedep/vet/actions/workflows/codeql.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/safedep/vet.svg)](https://pkg.go.dev/github.com/safedep/vet)

</div>

---

## 🎯 Why vet?

> **70-90% of modern software constitute code from open sources** — How do we know if it's safe?

**vet** is an open source software supply chain security tool built for **developers and security engineers** who need:

✅ **Next-gen Software Composition Analysis** — Vulnerability and malicious package detection  
✅ **Policy as Code** — Express opinionated security policies using [CEL](https://cel.dev/)    
✅ **Real-time malicious package detection** — Powered by [SafeDep Cloud](https://docs.safedep.io/cloud/malware-analysis) active scanning   
✅ **Multi-ecosystem support** — npm, PyPI, Maven, Go, Docker, GitHub Actions, and more    
✅ **CI/CD native** — Built for DevSecOps workflows with support for GitHub Actions, GitLab CI, and more   
✅ **MCP Server** — Run `vet` as a MCP server to vet open source packages from AI suggested code   

## ⚡ Quick Start

**Install in seconds:**

```bash
# macOS & Linux
brew install safedep/tap/vet
```

or download a [pre-built binary](https://github.com/safedep/vet/releases)

**Scan your project:**

```bash
# Scan current directory
vet scan -D .

# Scan a single file
vet scan -M package-lock.json

# Fail CI on critical vulnerabilities
vet scan -D . --filter 'vulns.critical.exists(p, true)' --filter-fail

# Fail CI on OpenSSF Scorecard requirements
vet scan -D . --filter 'scorecard.scores.Maintained < 5' --filter-fail

# Fail CI if a package is published from a GitHub repository with less than 5 stars
vet scan -D . --filter 'projects.exists(p, p.type == "GITHUB" && p.stars < 5)' --filter-fail
```

## 🔒 Key Features

### 🕵️ **Code Analysis**
Unlike dependency scanners that flood you with noise, `vet` analyzes your **actual code usage** to prioritize real risks. See [dependency usage evidence](https://docs.safedep.io/guides/dependency-usage-identification) for more details.

### 🛡️ **Malicious Package Detection**
Integrated with [SafeDep Cloud](https://docs.safedep.io/cloud/malware-analysis) for real-time protection against malicious packages in the wild. Free for open source projects. Fallback to *Query Mode* when API key is not provided. Read more [about malicious package scanning](#️-malicious-package-detection-1).

### 📋 **Policy as Code**
Define security policies using CEL expressions to enforce context specific security requirements.

```bash
# Block packages with critical CVEs
vet scan \
--filter 'vulns.critical.exists(p, true)'

# Enforce license compliance
vet scan \
--filter 'licenses.contains_license("GPL-3.0")'

# Enforce OpenSSF Scorecard requirements
# Require minimum OpenSSF Scorecard scores
vet scan \
--filter 'scorecard.scores.Maintained < 5'
```

### 🎯 **Multi-Format Support**
- **Package Managers**: npm, PyPI, Maven, Go, Ruby, Rust, PHP
- **Container Images**: Docker, OCI
- **SBOMs**: CycloneDX, SPDX
- **Binary Artifacts**: JAR files, Python wheels
- **Source Code**: Direct repository scanning

## 🔥 See vet in Action

<div align="center">
  <img src="./docs/assets/vet-demo.gif" alt="vet Demo" width="100%" />
</div>

## 🚀 Production Ready Integrations

### 📦 **GitHub Actions**
Zero config security guardrails against vulnerabilities and malicious packages in your CI/CD pipeline
**with your own opinionated policies**:

```yaml
- uses: safedep/vet-action@v1
  with:
    policy: '.github/vet/policy.yml'
```

See more in [vet-action](https://github.com/safedep/vet-action) documentation.

### 🔧 **GitLab CI**
Enterprise grade scanning with [vet CI Component](https://gitlab.com/explore/catalog/safedep/ci-components/vet):

```yaml
include:
  - component: gitlab.com/safedep/ci-components/vet@main
```

### 🐳 **Container Integration**
Run `vet` anywhere, even your internal developer platform or custom CI/CD environment using our container image.

```bash
docker run --rm -v $(pwd):/app ghcr.io/safedep/vet:latest scan -D /app
```

## 📚 Table of Contents

- [🎯 Why vet?](#-why-vet)
- [⚡ Quick Start](#-quick-start)
- [🔒 Key Features](#-key-features)
  - [🕵️ **Code Analysis**](#️-code-analysis)
  - [🛡️ **Malicious Package Detection**](#️-malicious-package-detection)
  - [📋 **Policy as Code**](#-policy-as-code)
  - [🎯 **Multi-Format Support**](#-multi-format-support)
- [🔥 See vet in Action](#-see-vet-in-action)
- [🚀 Production Ready Integrations](#-production-ready-integrations)
  - [📦 **GitHub Actions**](#-github-actions)
  - [🔧 **GitLab CI**](#-gitlab-ci)
  - [🐳 **Container Integration**](#-container-integration)
- [📚 Table of Contents](#-table-of-contents)
- [📦 Installation Options](#-installation-options)
  - [🍺 **Homebrew (Recommended)**](#-homebrew-recommended)
  - [📥 **Direct Download**](#-direct-download)
  - [🐹 **Go Install**](#-go-install)
  - [🐳 **Container Image**](#-container-image)
  - [⚙️ **Verify Installation**](#️-verify-installation)
- [🎮 Advanced Usage](#-advanced-usage)
  - [🔍 **Scanning Options**](#-scanning-options)
  - [🎯 **Policy Enforcement Examples**](#-policy-enforcement-examples)
  - [🔧 **SBOM Support**](#-sbom-support)
  - [📊 **Query Mode \& Data Persistence**](#-query-mode--data-persistence)
- [📊 Reporting](#-reporting)
  - [📋 **Report Formats**](#-report-formats)
  - [🎯 **Report Examples**](#-report-examples)
  - [🤖 **MCP Server**](#-mcp-server)
- [🛡️ Malicious Package Detection](#️-malicious-package-detection-1)
  - [🚀 **Quick Setup**](#-quick-setup)
  - [🎯 **Advanced Malicious Package Analysis**](#-advanced-malicious-package-analysis)
  - [🔒 **Security Features**](#-security-features)
- [📊 Privacy and Telemetry](#-privacy-and-telemetry)
- [🎊 Community \& Support](#-community--support)
  - [🌟 **Join the Community**](#-join-the-community)
  - [💡 **Get Help \& Share Ideas**](#-get-help--share-ideas)
  - [⭐ **Star History**](#-star-history)
  - [🙏 **Built With Open Source**](#-built-with-open-source)

## 📦 Installation Options

### 🍺 **Homebrew (Recommended)**
```bash
brew tap safedep/tap
brew install safedep/tap/vet
```

### 📥 **Direct Download**
See [releases](https://github.com/safedep/vet/releases) for the latest version.

### 🐹 **Go Install**
```bash
go install github.com/safedep/vet@latest
```

### 🐳 **Container Image**
```bash
# Quick test
docker run --rm ghcr.io/safedep/vet:latest version

# Scan local directory
docker run --rm -v $(pwd):/workspace ghcr.io/safedep/vet:latest scan -D /workspace
```

### ⚙️ **Verify Installation**
```bash
vet version
# Should display version and build information
```

## 🎮 Advanced Usage

### 🔍 **Scanning Options**

<table>
<tr>
<td width="50%">

**📁 Directory Scanning**
```bash
# Scan current directory
vet scan

# Scan a given directory
vet scan -D /path/to/project

# Resolve and scan transitive dependencies
vet scan -D . --transitive
```

**📄 Manifest Files**
```bash
# Package managers
vet scan -M package-lock.json
vet scan -M requirements.txt
vet scan -M pom.xml
vet scan -M go.mod
vet scan -M Gemfile.lock
```

</td>
<td width="50%">

**🐙 GitHub Integration**
```bash
# Setup GitHub access
vet connect github

# Scan repositories
vet scan --github https://github.com/user/repo

# Organization scanning
vet scan --github-org https://github.com/org
```

**📦 Artifact Scanning**
```bash
# Container images
vet scan --image nginx:latest
vet scan --image /path/to/image-saved-file.tar

# Binary artifacts
vet scan -M app.jar
vet scan -M package.whl
```

</td>
</tr>
</table>

### 🎯 **Policy Enforcement Examples**

```bash
# Security-first scanning
vet scan -D . \
  --filter 'vulns.critical.exists(p, true) || vulns.high.exists(p, true)' \
  --filter-fail

# License compliance
vet scan -D . \
  --filter 'licenses.contains_license("GPL-3.0")' \
  --filter-fail

# OpenSSF Scorecard requirements
vet scan -D . \
  --filter 'scorecard.scores.Maintained < 5' \
  --filter-fail

# Popularity-based filtering
vet scan -D . \
  --filter 'projects.exists(p, p.type == "GITHUB" && p.stars < 50)' \
  --filter-fail
```

### 🔧 **SBOM Support**

```bash
# Scan a CycloneDX SBOM
vet scan -M sbom.json --type bom-cyclonedx

# Scan a SPDX SBOM
vet scan -M sbom.spdx.json --type bom-spdx

# Generate SBOM output
vet scan -D . --report-cdx=output.sbom.json

# Package URL scanning
vet scan --purl pkg:npm/lodash@4.17.21
```

### 📊 **Query Mode & Data Persistence**

For large codebases and repeated analysis:

```bash
# Scan once, query multiple times
vet scan -D . --json-dump-dir ./scan-data

# Query with different filters
vet query --from ./scan-data \
  --filter 'vulns.critical.exists(p, true)'

# Generate focused reports
vet query --from ./scan-data \
  --filter 'licenses.contains_license("GPL")' \
  --report-json license-violations.json
```

## 📊 Reporting

**vet** generate reports that are tailored for different stakeholders:

### 📋 **Report Formats**

<table>
<tr>
<td width="30%"><strong>🔍 For Security Teams</strong></td>
<td width="70%">

```bash
# SARIF for GitHub Security tab
vet scan -D . --report-sarif=report.sarif

# JSON for custom tooling
vet scan -D . --report-json=report.json

# CSV for spreadsheet analysis
vet scan -D . --report-csv=report.csv
```

</td>
</tr>
<tr>
<td><strong>📖 For Developers</strong></td>
<td>

```bash
# Markdown reports for PRs
vet scan -D . --report-markdown=report.md

# Console summary (default)
vet scan -D . --report-summary
```

</td>
</tr>
<tr>
<td><strong>🏢 For Compliance</strong></td>
<td>

```bash
# SBOM generation
vet scan -D . --report-cdx=sbom.json

# Dependency graphs
vet scan -D . --report-graph=dependencies.dot
```

</td>
</tr>
</table>

### 🎯 **Report Examples**

```bash
# Multi-format output
vet scan -D . \
  --report-json=report.json \
  --report-sarif=report.sarif \
  --report-markdown=report.md

# Focus on specific issues
vet scan -D . \
  --filter 'vulns.high.exists(p, true)' \
  --report-json=report.json
```

### 🤖 **MCP Server**

**vet** can be used as an MCP server to vet open source packages from AI suggested code.

```bash
# Start the MCP server with SSE transport
vet server mcp --server-type sse
```

For more details, see [vet MCP Server](./docs/mcp.md) documentation.

## 🛡️ Malicious Package Detection

**Malicious package detection through active scanning and code analysis** powered by 
[SafeDep Cloud](https://docs.safedep.io/cloud/malware-analysis). `vet` requires an API
key for active scanning of unknown packages. When API key is not provided, `vet` will
fallback to *Query Mode* which detects known malicious packages from [SafeDep](https://safedep.io)
and [OSV](https://osv.dev) databases.

- Grab a free API key from [SafeDep Platform App](https://platform.safedep.io) or use `vet cloud quickstart`
- API access is free forever for open source projects
- No proprietary code is collected for malicious package detection
- Only open source package scanning from public repositories is supported

### 🚀 **Quick Setup**

> Malicious package detection requires an API key for [SafeDep Cloud](https://docs.safedep.io/cloud/malware-analysis).

```bash
# One-time setup
vet cloud quickstart

# Enable malware scanning
vet scan -D . --malware

# Query for known malicious packages without API key
vet scan -D . --malware-query
```

Example malicious packages detected and reported by [SafeDep Cloud](https://docs.safedep.io/cloud/malware-analysis)
malicious package detection:

- [MAL-2025-3541: express-cookie-parser](https://safedep.io/malicious-npm-package-express-cookie-parser/)
- [MAL-2025-4339: eslint-config-airbnb-compat](https://safedep.io/digging-into-dynamic-malware-analysis-signals/)
- [MAL-2025-4029: ts-runtime-compat-check](https://safedep.io/digging-into-dynamic-malware-analysis-signals/)
- [MAL-2025-2227: nyc-config](https://safedep.io/nyc-config-malicious-package/)

### 🎯 **Advanced Malicious Package Analysis**

<table>
<tr>
<td width="50%">

**🔍 Scan packages with malicious package detection enabled**
```bash
# Real-time scanning
vet scan -D . --malware

# Timeout adjustment
vet scan -D . --malware \
  --malware-analysis-timeout=300s

# Batch analysis
vet scan -D . --malware \
  --json-dump-dir=./analysis
```

</td>
<td width="50%">

**🎭 Specialized Scans**
```bash
# VS Code extensions
vet scan --vsx --malware

# GitHub Actions
vet scan -D .github/workflows --malware

# Container Images
vet scan --image nats:2.10 --malware

# Scan a single package and fail if its malicious
vet scan --purl pkg:/npm/nyc-config@10.0.0 --fail-fast

# Active scanning of a single package (requires API key)
vet inspect malware \
  --purl pkg:npm/nyc-config@10.0.0
```

</td>
</tr>
</table>

### 🔒 **Security Features**

- ✅ **Real-time analysis** of packages against known malware databases
- ✅ **Behavioral analysis** using static and dynamic analysis
- ✅ **Zero day protection** through active code scanning
- ✅ **Human in the loop** for triaging and investigation of high impact findings
- ✅ **Real time analysis** with public [analysis log](https://vetpkg.dev/mal)

## 📊 Privacy and Telemetry

`vet` collects anonymous usage telemetry to improve the product. **Your code and package information is never transmitted.**

```bash
# Disable telemetry (optional)
export VET_DISABLE_TELEMETRY=true
```

## 🎊 Community & Support

<div align="center">
  
### 🌟 **Join the Community**

[![Discord](https://img.shields.io/discord/1090352019379851304?color=7289da&label=Discord&logo=discord&logoColor=white)](https://rebrand.ly/safedep-community)
[![GitHub Discussions](https://img.shields.io/badge/GitHub-Discussions-green?logo=github)](https://github.com/safedep/vet/discussions)
[![Twitter Follow](https://img.shields.io/twitter/follow/safedepio?style=social)](https://twitter.com/safedepio)

</div>

### 💡 **Get Help & Share Ideas**

- 🚀 **[Interactive Tutorial](https://killercoda.com/safedep/scenario/101-intro)** - Learn vet hands-on
- 📚 **[Complete Documentation](https://docs.safedep.io/)** - Comprehensive guides
- 💬 **[Discord Community](https://rebrand.ly/safedep-community)** - Real-time support
- 🐛 **[Issue Tracker](https://github.com/safedep/vet/issues)** - Bug reports & feature requests
- 🤝 **[Contributing Guide](CONTRIBUTING.md)** - Join the development

---

<div align="center">

### ⭐ **Star History**

[![Star History Chart](https://api.star-history.com/svg?repos=safedep/vet&type=Date)](https://star-history.com/#safedep/vet&Date)

### 🙏 **Built With Open Source**

vet stands on the shoulders of giants:

[OSV](https://osv.dev) • [OpenSSF Scorecard](https://securityscorecards.dev/) • [SLSA](https://slsa.dev/) • [OSV-SCALIBR](https://github.com/google/osv-scalibr) • [Syft](https://github.com/anchore/syft)

---

<p><strong>⚡ Secure your supply chain today. Star the repo ⭐ and get started!</strong></p>

Created with ❤️ by [SafeDep](https://safedep.io) and the open source community

</div>

<img referrerpolicy="no-referrer-when-downgrade" src="https://static.scarf.sh/a.png?x-pxid=304d1856-fcb3-4166-bfbf-b3e40d0f1e3b" />
