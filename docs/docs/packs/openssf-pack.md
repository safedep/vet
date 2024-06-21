---
sidebar_position: 3
title: 🧰 OpenSSF Scorecard
draft: true
---

# 🧰 OpenSSF Scorecard

The following policy geared towards the OpenSSF Scorecard best practices. So you can use this `openssf-risk-pack.yaml` to perform the generic security checks.

```yaml title="openssf-risk-pack.yaml"
name: OpenSSF Scorecard Practices Checks
description: |
  This filter suite contains rules for implementing OpenSSF Scorecard
  security checks and best practices for an organization.
filters:
  - name: critical-or-high-vulns
    value: |
      vulns.critical.exists(p, true) || vulns.high.exists(p, true)
  - name: ossf-unmaintained
    value: |
      scorecard.scores["Maintained"] == 0
  - name: ossf-dangerous-workflow
    value: |
      scorecard.scores["Dangerous-Workflow"] == 0
```
