<div align="center">
  <img alt="SafeDep vet" src="./docs/assets/vet-logo-light.png#gh-light-mode-only" height="120" />
  <img alt="SafeDep vet" src="./docs/assets/vet-logo-dark.png#gh-dark-mode-only" height="120" />
  
  <h1>🔍 vet</h1>
  
  <p><strong>Enterprise-grade supply chain security for open source dependencies</strong></p>
  
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

</div>

---

## 🎯 Why vet?

> **87% of codebases contain vulnerable dependencies** — and traditional tools miss the context that matters.

**vet** is the first supply chain security tool built for **developers and security engineers** who need:

✅ **Zero false positives** — Only actionable insights that matter to your codebase  
✅ **Policy as Code** — Express complex security rules using [CEL](https://cel.dev/)  
✅ **Real-time malware detection** — Powered by SafeDep Cloud's active scanning  
✅ **Multi-ecosystem support** — npm, PyPI, Maven, Go, Docker, GitHub Actions, and more  
✅ **CI/CD native** — Built for DevSecOps workflows with GitHub Actions & GitLab CI  

## ⚡ Quick Start

**Install in seconds:**

```bash
# macOS & Linux
brew install safedep/tap/vet

# Or download from releases
curl -sSfL https://raw.githubusercontent.com/safedep/vet/main/install.sh | sh
```

**Scan your project:**

```bash
# Scan current directory
vet scan -D .

# Scan with malware detection
vet scan -D . --malware

# Fail CI on critical vulnerabilities
vet scan -D . --filter 'vulns.critical.exists(p, true)' --filter-fail
```

## 🔒 Enterprise Security Features

### 🕵️ **Intelligent Code Analysis**
Unlike dependency scanners that flood you with noise, vet analyzes your **actual code usage** to prioritize real risks.

### 🛡️ **Advanced Malware Detection**
Integrated with SafeDep Cloud for real-time protection against malicious packages in the wild.

### 📋 **Policy as Code**
Define sophisticated security policies using CEL expressions:

```bash
# Block packages with critical CVEs
--filter 'vulns.critical.exists(p, true)'

# Enforce license compliance
--filter 'licenses.contains_license("GPL-3.0")'

# Require minimum OpenSSF Scorecard scores
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

## 🚀 Production-Ready Integrations

### 📦 **GitHub Actions**
Zero-config security scanning for your CI/CD:

```yaml
- uses: safedep/vet-action@v1
  with:
    path: '.'
    malware: true
    policy: '.github/vet-policy.yml'
```

### 🔧 **GitLab CI**
Enterprise-grade scanning with [vet CI Component](https://gitlab.com/explore/catalog/safedep/ci-components/vet):

```yaml
include:
  - component: gitlab.com/safedep/ci-components/vet@main
```

### 🐳 **Container Integration**
```bash
docker run --rm -v $(pwd):/app ghcr.io/safedep/vet:latest scan -D /app
```

## 📚 Table of Contents

- [🎯 Why vet?](#-why-vet)
- [⚡ Quick Start](#-quick-start)
- [🔒 Enterprise Security Features](#-enterprise-security-features)
- [🔥 See vet in Action](#-see-vet-in-action)
- [🚀 Production-Ready Integrations](#-production-ready-integrations)
- [📦 Installation Options](#-installation-options)
- [🎮 Advanced Usage](#-advanced-usage)
- [📊 Comprehensive Reporting](#-comprehensive-reporting)
- [🛡️ Malware Detection](#️-malware-detection)
- [🎊 Community & Support](#-community--support)

## 📦 Installation Options

### 🍺 **Homebrew (Recommended)**
```bash
brew tap safedep/tap
brew install safedep/tap/vet
```

### 📥 **Direct Download**
```bash
# Latest release for your platform
curl -sSfL https://raw.githubusercontent.com/safedep/vet/main/install.sh | sh

# Or download manually from GitHub Releases
wget https://github.com/safedep/vet/releases/latest
```

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
# Scan entire project
vet scan -D /path/to/project

# Current directory
vet scan -D .

# With malware detection
vet scan -D . --malware
```

**📄 Manifest Files**
```bash
# Package managers
vet scan -M package.json
vet scan -M requirements.txt
vet scan -M pom.xml
vet scan -M go.mod
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
  --filter 'pkg.popularity.downloads.monthly < 1000' \
  --filter-fail
```

### 🔧 **SBOM & Standards Support**

```bash
# CycloneDX SBOM
vet scan -M sbom.json --type bom-cyclonedx

# SPDX SBOM
vet scan -M sbom.spdx.json --type bom-spdx

# Generate SBOM output
vet scan -D . --report-cyclonedx=output.sbom.json

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

## 📊 Comprehensive Reporting

**vet** generates reports tailored for different stakeholders:

### 📋 **Report Formats**

<table>
<tr>
<td width="30%"><strong>🔍 For Security Teams</strong></td>
<td width="70%">

```bash
# SARIF for GitHub Security tab
vet scan -D . --report-sarif=security.sarif

# JSON for custom tooling
vet scan -D . --report-json=detailed.json

# CSV for spreadsheet analysis
vet scan -D . --report-csv=analysis.csv
```

</td>
</tr>
<tr>
<td><strong>📖 For Developers</strong></td>
<td>

```bash
# Markdown reports for PRs
vet scan -D . --report-markdown=security-review.md

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
vet scan -D . --report-cyclonedx=sbom.json

# Dependency graphs
vet scan -D . --report-dot=dependencies.dot
```

</td>
</tr>
</table>

### 🎯 **Report Examples**

```bash
# Multi-format output
vet scan -D . \
  --report-json=results.json \
  --report-sarif=security.sarif \
  --report-markdown=summary.md

# Focus on specific issues
vet scan -D . \
  --filter 'vulns.high.exists(p, true)' \
  --report-json=high-severity.json
```

## 🛡️ Malware Detection

**Industry-leading malware detection** powered by SafeDep Cloud:

### 🚀 **Quick Setup**

```bash
# One-time setup
vet cloud quickstart

# Enable malware scanning
vet scan -D . --malware
```

### 🎯 **Advanced Malware Analysis**

<table>
<tr>
<td width="50%">

**🔍 Threat Intelligence**
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

# Specific packages
vet inspect malware \
  --purl pkg:npm/malicious-package@1.0.0
```

</td>
</tr>
</table>

### 🔒 **Security Features**

- ✅ **Real-time analysis** of packages against known malware databases
- ✅ **Behavioral analysis** using SafeDep Cloud's ML models  
- ✅ **Community intelligence** from Malysis service
- ✅ **Zero-day protection** through active code scanning
- ✅ **Privacy-first** design with optional cloud analysis

## 🎊 Community & Support

<div align="center">
  
### 🌟 **Join the Community**

[![Discord](https://img.shields.io/discord/1234567890?color=7289da&label=Discord&logo=discord&logoColor=white)](https://rebrand.ly/safedep-community)
[![GitHub Discussions](https://img.shields.io/badge/GitHub-Discussions-green?logo=github)](https://github.com/safedep/vet/discussions)
[![Twitter Follow](https://img.shields.io/twitter/follow/safedepio?style=social)](https://twitter.com/safedepio)

</div>

### 💡 **Get Help & Share Ideas**

- 🚀 **[Interactive Tutorial](https://killercoda.com/safedep/scenario/101-intro)** - Learn vet hands-on
- 📚 **[Complete Documentation](https://docs.safedep.io/)** - Comprehensive guides
- 💬 **[Discord Community](https://rebrand.ly/safedep-community)** - Real-time support
- 🐛 **[Issue Tracker](https://github.com/safedep/vet/issues)** - Bug reports & feature requests
- 🤝 **[Contributing Guide](CONTRIBUTING.md)** - Join the development

### 🏢 **Enterprise Support**

Need enterprise-grade support? **[SafeDep Cloud](https://safedep.io)** provides:

- ✅ Dedicated support team
- ✅ Custom policy development  
- ✅ Large-scale deployment assistance
- ✅ Integration consulting
- ✅ SLA guarantees

---

<div align="center">

### ⭐ **Star History**

[![Star History Chart](https://api.star-history.com/svg?repos=safedep/vet&type=Date)](https://star-history.com/#safedep/vet&Date)

### 🙏 **Built With Open Source**

vet stands on the shoulders of giants:

[OSV](https://osv.dev) • [OpenSSF Scorecard](https://securityscorecards.dev/) • [SLSA](https://slsa.dev/) • [OSV Scanner](https://github.com/google/osv-scanner) • [Syft](https://github.com/anchore/syft)

---

<p><strong>⚡ Secure your supply chain today. Star the repo ⭐ and get started!</strong></p>

Created with ❤️ by [SafeDep](https://safedep.io) and the open source community

</div>

### 📊 Privacy & Telemetry

vet collects anonymous usage telemetry to improve the product. **Your code and package information is never transmitted.**

```bash
# Disable telemetry (optional)
export VET_DISABLE_TELEMETRY=true
```

<img referrerpolicy="no-referrer-when-downgrade" src="https://static.scarf.sh/a.png?x-pxid=304d1856-fcb3-4166-bfbf-b3e40d0f1e3b" />
