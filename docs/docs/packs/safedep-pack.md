---
sidebar_position: 6
title: 🧰 SafeDep
draft: true
---

# 🧰 SafeDep Best Practices

The following policy geared towards the SafeDep opinionated best practices. So you can use this `safedep-risk-pack.yaml` to perform the security checks.

```yaml title="safedep-risk-pack.yaml"
name: SafeDep Best Practices
description: |
  This filter suite contains rules for implementing SafeDep
  security checks and best practices for an organization.
filters:
  - name: critical-or-high-vulns
    value: |
      vulns.critical.exists(p, true) || vulns.high.exists(p, true)
  - name: low-popularity
    value: |
      projects.exists(p, (p.type == "GITHUB") && (p.stars < 50))
  - name: risky-oss-licenses
    value: |
      licenses.exists(p, p == "GPL-2.0") ||
      licenses.exists(p, p == "GPL-3.0") ||
      licenses.exists(p, p == "AGPL-3.0")
  - name: ossf-unmaintained
    value: |
      scorecard.scores["Maintained"] == 0
  - name: ossf-dangerous-workflow
    value: |
      scorecard.scores["Dangerous-Workflow"] == 0
```
