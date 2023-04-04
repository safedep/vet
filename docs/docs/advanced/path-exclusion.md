---
sidebar_position: 6
title: 🚧 Path Exclusion
---

# 🚧 Path Exclusion

`vet` supports path exclusions for scenarios where a directory is the scan target but certain path patterns within the directory should be excluded from scan. This is available only for the `scan` command.

```bash
vet scan -D /path/to/target --exclude 'docs/*'
```

- Multiple path patterns can be provided for exclusion while scanning a directory

```bash
vet scan -D /path/to/target \
    --exclude 'docs/*' \
    --exclude 'sub/dir/path/*'
```

:::info

The exclusion pattern matches any path, directory or file. Internally it uses
Go regexp [MatchString](https://pkg.go.dev/regexp#MatchString)

:::
