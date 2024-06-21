---
sidebar_position: 2
title: 🚀 Quick Start
---

# 🚀 Quick Start

- Download the binary file for your operating system/architecture from the [Official GitHub Releases](https://github.com/safedep/vet/releases) or look at [different installation options](installation.mdx).

- Run `vet` to identify risks

```bash
vet scan -D /path/to/repository
```

![vet scan directory](/img/vet/vet-scan-directory.png)

- You can also scan a specific (supported) package manifest

```bash
vet scan --lockfiles /path/to/pom.xml
vet scan --lockfiles /path/to/requirements.txt
vet scan --lockfiles /path/to/package-lock.json
```

:::info

To list all available package manifest parsers run
`vet scan parsers --experimental`

:::

![vet scan files](/img/vet/vet-scan-files.png)
