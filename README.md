<h1 align="center">
    <img alt="SafeDep Vet" src="docs/static/img/vet-logo.png" width="150" />
</h1>
<p align="center">
    🙌 Refer to <b><a href="https://safedep.io/docs/">https://safedep.io/docs</a></b> for the documentation 📖
</p>

[![Go Report Card](https://goreportcard.com/badge/github.com/safedep/vet)](https://goreportcard.com/report/github.com/safedep/vet)
![License](https://img.shields.io/github/license/safedep/vet)
![Release](https://img.shields.io/github/v/release/safedep/vet)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/safedep/vet/badge)](https://api.securityscorecards.dev/projects/github.com/safedep/vet)
[![CodeQL](https://github.com/safedep/vet/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/safedep/vet/actions/workflows/codeql.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Scorecard supply-chain security](https://github.com/safedep/vet/actions/workflows/scorecard.yml/badge.svg)](https://github.com/safedep/vet/actions/workflows/scorecard.yml)
[![Twitter](https://img.shields.io/twitter/follow/safedepio?style=social)](https://twitter.com/intent/follow?screen_name=safedepio)

[![vet banner](docs/static/img/vet/vet-banner.png)](https://safedep.io/docs)

## Automate Open Source Package Vetting in CI/CD

`vet` is a tool for identifying risks in open source software supply chain. It
goes beyond just vulnerabilities and provides visibility on OSS package risks
due to it's license, popularity, security hygiene, and more. `vet` is designed
with the goal of enabling trusted OSS package consumption by integrating with
CI/CD and `policy as code` as guardrails.

* [🔥 vet in action](#-vet-in-action)
* [Getting Started](#getting-started)
  * [Running Scan](#running-scan)
    * [Scanning SBOM](#scanning-sbom)
    * [Scanning Github Repositories](#scanning-github-repositories)
    * [Scanning Github Organization](#scanning-github-organization)
    * [Scanning Package URL](#scanning-package-url)
    * [Available Parsers](#available-parsers)
* [Policy as Code](#policy-as-code)
* [CI/CD Integration](#ci/cd-integration)
  * [📦 GitHub Action](#-github-action)
  * [🚀 GitLab CI](#-gitlab-ci)
* [🛠️ Advanced Usage](#-advanced-usage)
* [📖 Documentation](#-documentation)
* [🎊 Community](#-community)
* [💻 Development](#-development)
* [Star History](#star-history)
* [🔖 References](#-references)

## 🔥 vet in action

![vet Demo](docs/static/img/vet/vet-demo.gif)

## Getting Started

- Download the binary file for your operating system / architecture from the [Official GitHub Releases](https://github.com/safedep/vet/releases)

- You can also install `vet` using homebrew in MacOS and Linux

```bash
brew tap safedep/tap
brew install safedep/tap/vet
```

- Alternatively, build from source

> Ensure $(go env GOPATH)/bin is in your $PATH

```bash
go install github.com/safedep/vet@latest
```

- Also available as a container image

```bash
docker run --rm -it ghcr.io/safedep/vet:latest version
```

> **Note:** Container image is built for x86_64 Linux only. Use a
> [pre-built binary](https://github.com/safedep/vet/releases) or
> build from source for other platforms.

### Running Scan

- Run `vet` to identify risks by scanning a directory

```bash
vet scan -D /path/to/repository
```

![vet scan directory](docs/static/img/vet/vet-scan-directory.png)

- Run `vet` to scan specific (supported) package manifests

```bash
vet scan --lockfiles /path/to/pom.xml
vet scan --lockfiles /path/to/requirements.txt
vet scan --lockfiles /path/to/package-lock.json
```

#### Scanning SBOM

- Scan an SBOM in [CycloneDX](https://cyclonedx.org/) format

```bash
vet scan --lockfiles /path/to/cyclonedx-sbom.json --lockfile-as bom-cyclonedx
```

- Scan an SBOM in [SPDX](https://spdx.dev/) format

```bash
vet scan --lockfiles /path/to/spdx-sbom.json --lockfile-as bom-spdx
```

> **Note:** SBOM scanning feature is currently in experimental stage

#### Scanning Github Repositories

- Setup github access token to scan private repo

```bash
vet connect github
```

Alternatively, set `GITHUB_TOKEN` environment variable with [Github PAT](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)

- To scan remote Github repositories, including private ones

```bash
vet scan --github https://github.com/safedep/vet
```

**Note:** You may need to enable [Dependency Graph](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph) at repository or organization level for Github repository scanning to work.

#### Scanning Github Organization

> You must setup the required access for scanning private repositories
> before scanning organizations

```bash
vet scan --github-org https://github.com/safedep
```

> **Note:** `vet` will block and wait if it encounters Github secondary rate limit.

#### Scanning Package URL

- To scan a [purl](https://github.com/package-url/purl-spec)

```bash
vet scan --purl pkg:/gem/nokogiri@1.10.4
```

#### Available Parsers

- List supported package manifest parsers including experimental modules

```bash
vet scan parsers --experimental
```

## Policy as Code

`vet` uses [Common Expressions Language](https://github.com/google/cel-spec)
(CEL) as the policy language. Policies can be defined to build guardrails
preventing introduction of insecure components.

- Run `vet` and fail if a critical or high vulnerability was detected

```bash
vet scan -D /path/to/code \
    --filter 'vulns.critical.exists(p, true) || vulns.high.exists(p, true)' \
    --filter-fail
```

- Run `vet` and fail if a package with a specific license was detected

```bash
vet scan -D /path/to/code \
    --filter 'licenses.exists(p, p == "GPL-2.0")' \
    --filter-fail
```

- Run `vet` and fail based on [OpenSSF Scorecard](https://securityscorecards.dev/) attributes

```bash
vet scan -D /path/to/code \
    --filter 'scorecard.scores.Maintained == 0' \
    --filter-fail
```

For more examples, refer to [documentation](https://docs.safedep.io/advanced/polic-as-code)

## CI/CD Integration

### 📦 GitHub Action

- `vet` is available as a GitHub Action, refer to [vet-action](https://github.com/safedep/vet-action)

### 🚀 GitLab CI

- `vet` can be integrated with GitLab CI, refer to [vet-gitlab-ci](https://docs.safedep.io/integrations/gitlab-ci)

## 🛠️ Advanced Usage

- [Threat Hunting with vet](https://docs.safedep.io/advanced/filtering)
- [Policy as Code](https://docs.safedep.io/advanced/polic-as-code)
- [Exceptions and Overrides](https://docs.safedep.io/advanced/exceptions)

## 📖 Documentation

- Refer to [https://safedep.io/docs](https://safedep.io/docs) for the detailed documentation

[![vet docs](docs/static/img/vet-docs.png)](https://safedep.io/docs)

## 🎊 Community

First of all, thank you so much for showing interest in `vet`, we appreciate it ❤️

- Join the Discord server using the link - [https://rebrand.ly/safedep-community](https://rebrand.ly/safedep-community)

[![SafeDep Discord](docs/static/img/safedep-discord.png)](https://rebrand.ly/safedep-community)

## 💻 Development

Refer to [CONTRIBUTING.md](CONTRIBUTING.md)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=safedep/vet&type=Date)](https://star-history.com/#safedep/vet&Date)

## 🔖 References

- https://github.com/google/osv-scanner
- https://deps.dev/
- https://securityscorecards.dev/
- https://slsa.dev/
