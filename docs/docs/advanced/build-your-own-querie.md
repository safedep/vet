---
sidebar_position: 2
title: ✍️ Build Your Own Queries
---

# ✍️ Build Your Own Queries (BYOQ)

## Query Workflow

Scanning a package manifest is a resource intensive process as it involves enriching package metadata by querying Insights API. However, filtering and reporting may be done multiple times on the same manifest. To speed up the process, we can dump the enriched data as JSON and load the same for filtering and reporting.

- Dump enriched JSON manifests to a directory (example)

```bash
vet scan --lockfile /path/to/package-lock.json --json-dump-dir /tmp/dump
vet scan -D /path/to/repository --json-dump-dir /tmp/dump-many
```

- Load the enriched metadata for filtering and reporting

```bash
vet query --from /tmp/dump --report-summary
vet query --from /tmp/dump --filter 'scorecard.score.Maintained == 0'
```

## Security Guardrails with Filters

A simple security guardrail (in CI) can be achieved using the filters. The `--filter-fail` argument tells the `Filter Analyzer` module to fail the command if any package matches the given filter.

- Example: If OpenSSF Scorecard not maintained project score is `0` then fail the build

```bash
vet query --from /path/to/json-dump \
    --filter 'scorecard.scores.Maintained == 0' \
    --filter-fail
```

- Subsequently, the command fails with `-1` exit code in case of match

```bash
➜  vet git:(develop) ✗ echo $?
255
```
