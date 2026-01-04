# Reporting

`vet` generates reports in multiple formats to fit different workflows. Use `vet scan -h` to see all available reporting options.

## Common Reporters

### Summary Report 
Console output with vulnerability stats and prioritized remediation advice.

```bash
# Default behavior
vet scan -D .

# Show top 10 recommendations
vet scan -D . --report-summary-max-advice 10
```

### SARIF Report
For GitHub Code Scanning and IDE integration.

```bash
vet scan -D . --report-sarif results.sarif
```

**GitHub Actions Example**:
```yaml
- name: Run vet
  run: vet scan -D . --report-sarif results.sarif

- name: Upload to GitHub
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### JSON Report
Machine readable format for integrations and data processing.

```bash
vet scan -D . --report-json findings.json
```

### Markdown Summary
GitHub PR friendly reports with collapsible sections.

```bash
vet scan -D . --report-markdown-summary pr-comment.md
```

### CycloneDX SBOM
Standard SBOM format for compliance and supply chain transparency.

```bash
vet scan -D . --report-cdx sbom.json
```

### HTML Dashboard
Interactive visual report for sharing with stakeholders.

```bash
vet scan -D . --report-html security-report.html
```

## Using Multiple Reports

Generate multiple formats in a single scan:

```bash
vet scan -D . \
  --report-sarif results.sarif \
  --report-json findings.json \
  --report-html dashboard.html
```

## CI/CD Examples

**GitHub Actions**:
```bash
vet scan -D . \
  --report-sarif results.sarif \
  --report-markdown-summary pr-comment.md
```

**GitLab CI**:
```bash
vet scan -D . --report-gitlab gl-dependency-scanning.json
```

## Query Mode

Scan once, analyze multiple times without re-scanning:

```bash
# Scan and save data
vet scan -D . --json-dump-dir ./scan-data

# Query with different filters
vet query --from ./scan-data \
  --filter 'vulns.critical.exists(p, true)' \
  --report-json critical.json

vet query --from ./scan-data \
  --filter 'licenses.contains_license("GPL-3.0")' \
  --report-csv licenses.csv
```

## All Available Reporters

Run `vet scan -h` to see the complete list of reporters and options:

- `--report-summary` - Console summary (default)
- `--report-console` - Interactive table output
- `--report-sarif` - SARIF format
- `--report-json` - JSON format
- `--report-markdown` - Detailed markdown
- `--report-markdown-summary` - PR-friendly summary
- `--report-html` - Interactive HTML dashboard
- `--report-csv` - CSV export
- `--report-cdx` - CycloneDX SBOM
- `--report-gitlab` - GitLab format
- `--report-sqlite3` - SQLite database
- `--report-graph` - Dependency graphs (Graphviz)
- `--report-defect-dojo` - DefectDojo integration
- `--report-sync` - SafeDep Cloud sync

## Additional Resources

- [vet Documentation](https://docs.safedep.io/)
- [GitHub Actions Integration](https://github.com/safedep/vet-action)
- [SafeDep Cloud](https://docs.safedep.io/cloud/quickstart)
