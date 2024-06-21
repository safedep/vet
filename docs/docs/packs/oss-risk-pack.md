---
sidebar_position: 1
title: 🧰 OSS Best Practices
draft: true
---

# 🧰 OSS Best Practices

The following policy geared towards the generic OSS best practices. So you can use this `oss-risk-pack.yaml` to perform the generic security checks.

```yaml title="oss-risk-pack.yaml"
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
