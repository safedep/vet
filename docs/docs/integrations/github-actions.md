---
sidebar_position: 1
title: 🔁 Github Actions
---

# 🔁 Github Actions Workflow - Vet

- Make sure to get the registration key as `VET_INSIGHTS_API_KEY` and store in the Github Secrets of the repository

![Github Action Secret](/img/vet/github-action-secret-add.png)

- The following is the Github actions workflow file

```yml title=".github/workflows/vet.yml"
name: OSS Vet
on:
  pull_request:
    types: [opened, synchronize, reopened]
    branches: [ main ]

jobs:
  vet:
    name: Vet OSS Security
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run Vet
        run: |
          docker run \
            -u $(id -u ${USER}):$(id -g ${USER}) \
            -e VET_INSIGHTS_API_KEY=${{ secrets.VET_INSIGHTS_API_KEY }} \
            -v `pwd`:/code \
            ghcr.io/safedep/vet:latest \
            scan -s -D /code \
            --exceptions /code/.vet/exceptions.yml \
            --filter-suite /code/.vet/oss-risk-pack.yml \
            --filter-fail \
            --report-markdown=/code/vet.md
      - name: Add Vet Report to Summary
        run: cat vet.md >> $GITHUB_STEP_SUMMARY
```

- The policy pack applied is as following [OSS Best Practices](../packs/oss-risk-pack.md)

:::tip

- We have many policy packs available at [Query Packs](../packs/)
- You can also write your custom policy as a code, refer to [PaaC](../advanced/polic-as-code.md)

:::

```yml title=".vet/oss-risk-pack.yml"
name: General Purpose OSS Best Practices
description: |
  This filter suite contains rules for implementing general purpose OSS
  consumption best practices for an organization.
filters:
  - name: critical-or-high-vulns
    value: |
      vulns.critical.exists(p, true) || vulns.high.exists(p, true)
  - name: low-popularity
    value: |
      projects.exists(p, (p.type == "GITHUB") && (p.stars < 10))
  - name: risky-oss-licenses
    value: |
      licenses.exists(p, p == "GPL-2.0") ||
      licenses.exists(p, p == "GPL-3.0")
  - name: ossf-unmaintained
    value: |
      scorecard.scores["Maintained"] == 0
  - name: ossf-dangerous-workflow
    value: |
      scorecard.scores["Dangerous-Workflow"] == 0
```

## 🚀 Real-world example of vet in action

- The following is the example of how `vet` can be leveraged to enable security guardrails for your pipelines and continuous workflows using security packs [https://github.com/safedep/demo-client-java/pull/2](https://github.com/safedep/demo-client-java/actions/runs/4249672653/jobs/7390102023) for an insecure dependency

![github action real-world example](/img/vet/vet-github-action-real-world.png)
