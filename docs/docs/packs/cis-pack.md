---
sidebar_position: 2
title: 🧰 CIS Benchmarks
draft: true
---

# 🧰 CIS Benchmarks

The following policy geared towards the CIS benchmarks based guidelines towards security risks on libraries, software and in general. You can use this `cis-risk-pack.yaml` to perform the CIS Benchmarks security checks.

```yaml title="cis-risk-pack.yaml"
name: CIS Benchmarks Security Risks & Best Practices
description: |
  This filter suite contains rules for implementing based on CIS benchmarks
  and best practices for an organization.
filters:
  - name: critical-or-high-vulns
    value: |
      vulns.critical.exists(p, true) || vulns.high.exists(p, true)
  - name: ossf-unmaintained
    value: |
      scorecard.scores["Maintained"] == 0
```
