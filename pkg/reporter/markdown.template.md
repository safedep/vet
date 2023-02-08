# Vet Report

## Summary

|           |                       |
|-----------|-----------------------|
| Manifests | {{ .ManifestsCount }} |
| Packages  | {{ .PackagesCount }}  |

## Results

| Manifest | Ecosystem | Packages | :x: Packages with Issues |
|----------|-----------|----------|--------------------------|
{{- range $key, $value := .Summary }}
| {{ $key }} | {{ $value.Ecosystem }} | {{ $value.PackageCount }} | {{ $value.PackageWithIssuesCount }} |
{{- end }}

## Remediation Advice

The table below lists advice for dependency upgrade to mitigate one or more
issues identified during the scan.

{{ range $key, $value := .Remediations }}
> {{ $key }}

| Package | Update Version | Risk Score | Issues |
|---------|----------------|------------|--------|
{{- range $value }}
| {{ .PkgRemediationName }} | {{ .Pkg.Insights.PackageCurrentVersion }} | {{ .Score }} | - |
{{- end }}
{{ end }}



