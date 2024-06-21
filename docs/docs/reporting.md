---
sidebar_position: 7
title: 📝 Reporting
---

# 📝 Vet Reporting

`vet` default scan uses an opinionated [Summary Reporter](https://github.com/safedep/vet/blob/main/pkg/reporter/markdown.template.md) which presents a consolidated summary of findings. Thats NOT about it. Read more for expression based filtering and policy evaluation.

## Summary Report

- The default output format for the `vet` is console with summary. You can run the following command to get the summary report `--report-summary` flag. Which is basically a summary report with actionable advice.

```bash
vet scan --report-summary -D demo-client-java
```

![vet summary report](/img/vet/vet-report-summary.png)

## JSON Report

:::caution

The JSON report generator is currently in experimental state. The JSON schema
may change without notice.

:::

```bash
vet scan --report-json /path/to/report.json -D demo-client-java
```

## Markdown

- You can run the Markdown output format for the `vet` using `--report-markdown` flag. Which it generates consolidated markdown report to file.

```bash
vet scan --report-markdown=vet-markdown-report.md -D demo-client-java
```

![vet markdown report file](/img/vet/vet-markdown-report-file.png)

## SARIF

- You can run the SARIF output format for the `vet` using `--report-sarif` flag. Which it generates consolidated SARIF report to file.

```bash
vet scan --report-sarif=vet-sarif-report.sarif -D demo-client-java
```

## CSV

- You can run the CSV output format for the `vet` using `--report-csv` flag.

```bash
vet scan --report-csv=vet-csv-report.csv -D demo-client-java
```
