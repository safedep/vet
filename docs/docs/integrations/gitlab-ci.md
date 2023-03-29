---
sidebar_position: 2
title: 🔁 Gitlab CI/CD
---

# 🔁 Gitlab CI/CD Workflow - Vet

```yml
image:
    name: ghcr.io/safedep/vet:latest
    entrypoint: [""]

stages:
    - vet

oss-vet-scan:
    stage: vet
    script:
        - vet scan -s -D ${PWD} --report-markdown=${PWD}/vet-results.md
    artifacts:
        name: vet-results.md
        paths:
            - vet-results.md
        when: always
```
