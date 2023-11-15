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
helps engineering and security teams to identify potential issues in their open
source dependencies and evaluate them against organizational policies.

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
go install github.com/safedep/vet@main
```

- Configure `vet` to use community mode for Insights API

```bash
vet auth configure --community
```

> Insights API is used to enrich OSS packages with metadata for rich query and policy decisions.

- You can verify the configured key is successful by running the following command

```bash
vet auth verify
```

### Running Scan

- Run `vet` to identify risks

```bash
vet scan -D /path/to/repository
```

![vet scan directory](docs/static/img/vet/vet-scan-directory.png)

- You can also scan a specific (supported) package manifest

```bash
vet scan --lockfiles /path/to/pom.xml
vet scan --lockfiles /path/to/requirements.txt
vet scan --lockfiles /path/to/package-lock.json
```

> [Example Security Gate](https://github.com/safedep/demo-client-java/pull/2) using `vet` to prevent introducing new OSS dependency risk in an application.

#### Scanning SBOM

- To scan an SBOM in [CycloneDX](https://cyclonedx.org/) format

```bash
vet scan --lockfiles /path/to/cyclonedx-sbom.json --lockfile-as bom-cyclonedx
```

- To scan an SBOM in [SPDX](https://spdx.dev/) format

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

- To list supported package manifest parsers including experimental modules

```bash
vet scan parsers --experimental
```

## 📖 Documentation

- Refer to [https://safedep.io/docs](https://safedep.io/docs) for the detailed documentation

[![vet docs](docs/static/img/vet-docs.png)](https://safedep.io/docs)

## 🎊 Community

First of all, thank you so much for showing interest in `vet`, we appreciate it ❤️

- Join the server using the link - [https://rebrand.ly/safedep-community](https://rebrand.ly/safedep-community)

[![SafeDep Discord](docs/static/img/safedep-discord.png)](https://rebrand.ly/safedep-community)

## 💻 Development

## Requirements

* Go 1.21+

### Setup

* Install [ASDF](https://asdf-vm.com/)
* Install the development tools

```bash
asdf install
```

* Install `lefthook`

```bash
go install github.com/evilmartians/lefthook@latest
```

* Install git hooks

```bash
$(go env GOPATH)/bin/lefthook install
```

### Build

Install build tools

```bash
make dev-setup
```

Generate code from API specs and build `vet`

```bash
make
```

Quick build without regenerating code from API specs

```bash
make quick-vet
```

### Run Tests

```bash
go test -v ./...
```

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=safedep/vet&type=Date)](https://star-history.com/#safedep/vet&Date)

## 🔖 References

- [https://github.com/google/osv-scanner](https://github.com/google/osv-scanner)
