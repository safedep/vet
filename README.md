<h1 align="center">
    <img alt="SafeDep Vet" src="docs/static/img/vet-logo.png" width="150" />
</h1>
<p align="center">
    🙌 Refer to <b><a href="https://safedep.io/docs/">https://safedep.io/docs</a></b> for the documentation 📖
</p>

![License](https://img.shields.io/github/license/safedep/vet)
![Release](https://img.shields.io/github/v/release/safedep/vet)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/safedep/vet/badge)](https://api.securityscorecards.dev/projects/github.com/safedep/vet)
[![CodeQL](https://github.com/safedep/vet/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/safedep/vet/actions/workflows/codeql.yml)
[![Scorecard supply-chain security](https://github.com/safedep/vet/actions/workflows/scorecard.yml/badge.svg)](https://github.com/safedep/vet/actions/workflows/scorecard.yml)

![vet banner](docs/static/img/vet/vet-banner.png)
## Automate Open Source Package Vetting in CI/CD

`vet` is a tool for identifying risks in open source software supply chain. It
helps engineering and security teams to identify potential issues in their open
source dependencies and evaluate them against organizational policies.

## 🔥 vet in action

![vet Demo](docs/static/img/vet/vet-demo.gif)

## Getting Started

- Download the binary file for your operating system/architecture from the [Official GitHub Releases](https://github.com/safedep/vet/releases)

- Get an API key for the vet insights data access for performing the scan

```bash
vet auth trial --email john.doe@example.com
```

![vet register trial](docs/static/img/vet/vet-register-trial.png)

> A time limited trial API key will be sent over email.

- Configure `vet` to use API key to access the insights

```bash
vet auth configure
```

![vet configure](docs/static/img/vet/vet-configure.png)

> Insights API is used to enrich OSS packages with metadata for rich query and policy decisions. Alternatively, the API key can be passed through environment variable `VET_API_KEY`

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


## 📖 Documentation

- Refer to [https://safedep.io/docs](https://safedep.io/docs) for the detailed documentation

[![vet docs](docs/static/img/vet-docs.png)](https://safedep.io/docs)

## 🎊 Community

First of all, thank you so much for showing interest in `vet`, we appreciate it ❤️

- Join the server using the link - [https://rebrand.ly/safedep-community](https://rebrand.ly/safedep-community)

[![SafeDep Discord](docs/static/img/safedep-discord.png)](https://rebrand.ly/safedep-community)

## 🔖 References

- [https://github.com/google/osv-scanner](https://github.com/google/osv-scanner)
