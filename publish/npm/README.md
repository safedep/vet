# 🔍 vet

Enterprise-grade open source software supply chain security in one CLI.

This package delivers the `vet` binary via npm for teams that prefer Node.js tooling for install & upgrades.
Full project: https://github.com/safedep/vet • Docs: https://docs.safedep.io/

## ✨ What It Does

- Detects vulnerabilities (context & usage aware)
- Flags malicious / typosquatted packages (active + reputation)
- Enforces “Policy as Code” (licenses, popularity, scorecards) with CEL filters
- Works across ecosystems: npm, PyPI, Maven, Go, containers, SBOMs
- Outputs actionable reports: JSON, SARIF, Markdown, CycloneDX SBOM

## 📦 Install

```bash
npm install -g @safedep/vet
```

Check:
```bash
vet version
```

(Alternative installs: brew, direct binary, see upstream README.)

## ⚡ Quick Start

```bash
# Scan current project (auto-detect lock/manifests)
vet scan -D .

# Scan a specific manifest
vet scan -M package-lock.json
```

## 🛡 Basic Policies

```bash
# Fail on critical vulns
vet scan -D . --filter 'vulns.critical.exists(p, true)' --filter-fail

# License guard (example)
vet scan -D . --filter 'licenses.contains_license("GPL-3.0")' --filter-fail

# Scorecard maintenance threshold
vet scan -D . --filter 'scorecard.scores.Maintained < 5' --filter-fail
```

## 🔬 Malware Detection

```bash
# Setup (get API key)
vet cloud quickstart

# Active malicious package analysis
vet scan -D . --malware

# Known-malicious lookup only (no key)
vet scan -D . --malware-query
```

## 📊 Reports

```bash
vet scan -D . \
  --report-json=report.json \
  --report-sarif=report.sarif \
  --report-markdown=report.md
```

Generate SBOM:
```bash
vet scan -D . --report-cdx=sbom.json
```

## 🧪 Re-query Saved Data

```bash
vet scan -D . --json-dump-dir ./.vet-scan
vet query --from ./.vet-scan --filter 'vulns.high.exists(p, true)'
```

## 🤖 Integrations

GitHub Action: safedep/vet-action

GitLab Component: safedep/ci-components/vet

Container: ghcr.io/safedep/vet:latest

---
For complete documentation, advanced usage, troubleshooting, and more information, please visit: github.com/safedep/vet
