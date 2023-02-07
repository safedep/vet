# Vet Report

## Summary

* {{ .ManifestsCount }} manifest(s) were scanned
* {{ .PackagesCount }} packages were analyzed

## Remediation Advice

The table below lists advice for dependency upgrade to mitigate one or more
issues identified during the scan.

| Package | Update Version | Risk Score | Issues |
|---------|----------------|------------|--------|
{{- range .Remediations }}
| {{ .PkgRemediationName }} | {{ .Pkg.Insights.PackageCurrentVersion }} | {{ .Score }} | - |
{{- end }}


