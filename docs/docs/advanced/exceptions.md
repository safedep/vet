---
sidebar_position: 4
title: ❗ Exceptions
---

# ❗ Vet - Exceptions Management

Any security scanning tool may produce

1. False positive
2. Issues that are acceptable for a period of time
3. Issues that are ignored permanently

:::info

To support exceptions, we introduce the exception model defined in [exception spec](https://github.com/safedep/vet/blob/main/api/exceptions_spec.proto)

:::

## Use-case

As a user of `vet` tool, I want to add all existing packages or package versions as `exceptions` to make the scanner and filter analyses to ignore them while reporting issues so that I can deploy `vet` as a security guardrail to prevent introducing new packages with security issues

This workflow will allow users to

1. Accept the current issues as backlog to be mitigated over time
2. Deploy `vet` as a security gate in CI to prevent introducing new issues

### Security Risks

Exceptions management should handle the potential security risk of ignoring a package and its future issues. To mitigate this risk, we will ensure that issues can be ignored till an acceptable time window and not permanently.

## Workflow

### Generate Exceptions File

- Run a scan and dump raw data to a directory

```bash
vet scan -D /path/to/repo --json-dump-dir /path/to/dump
```

- Use `vet query` to generate exceptions for all existing packages

```bash
vet query --from /path/to/dump \
    --exceptions-generate /path/to/exceptions.yml \
    --exceptions-filter 'true' \    # Optional filter for packages to add
    --exceptions-till '2023-12-12'
```

:::info

`--exceptions-till` is parsed as `YYYY-mm-dd` and will generate a timestamp of `00:00:00` in UTC timezone for the date in RFC3339 format

:::

### Customize Exceptions File

The generated exceptions file will add all packages, matching optional filter, into the `exceptions.yml` file. This file should be reviewed and customised as required before using it.

### Use Exceptions to Ignore Specific Packages

An exceptions file can be passed as a global flag to `vet`. It will be used for various commands such as `scan` or `query`.

```bash
./vet --exceptions /path/to/exceptions.yml scan -D /path/to/repo
```

:::caution

Do not pass this flag while generating exceptions list in query workflow to avoid incorrect exception list generation

:::

## Behavior

- All exceptions rules are applied only on a `Package`
- All comparisons will be case-insensitive except version
- Only `version` can have a value of `*` matching any version
- Exceptions are globally managed and will be shared across packages
- Exempted packages will be ignored by all analysers and reporters
- First match policy for exceptions matching

Anti-patterns that will NOT be implemented

- Exceptions will not be implemented for manifests because they will cause false negatives
- Exceptions will not be created without an expiry to avoid future false negatives on the package
