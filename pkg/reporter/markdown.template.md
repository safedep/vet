# Vet Report

## Summary

|           |                       |
|-----------|-----------------------|
| Critical Vulns  | {{ .CriticalVulnCount }}  |
| High Vulns  | {{ .HighVulnCount }}  |
| Other Vulns  | {{ .OtherVulnCount }}  |
| Unpopular Packages  | {{ .UnpopularLibsCount }}  |
| Major Version Differences  | {{ .DriftLibsCount }}  |
| Manifests | {{ .ManifestsCount }} |
| Total Packages  | {{ .PackagesCount }}  |
| Exepmted Packages | {{.ExemptedLibs}} |




## Results

| Manifest | Ecosystem | Packages | Need Update |
|----------|-----------|----------|--------------------------|
{{- range $key, $value := .Summary }}
| {{ $key }} | {{ $value.Ecosystem }} | {{ $value.PackageCount }} | {{ $value.PackageWithIssuesCount }} |
{{- end }}

## Policy Violation

{{ if .Violations }}
| Ecosystem | Package | Reason |
|-----------|---------|--------|
{{- range $value := .Violations }}
| {{ $value.Ecosystem }} | {{ $value.PkgName }} | {{ $value.Message }} |
{{- end }}
{{ else }}
> No policy violation found or policy not configured during scan
{{ end }}

## Remediation Advice

The table below lists advice for dependency upgrade to mitigate one or more
issues identified during the scan.

{{ range $key, $value := .Remediations }}
> {{ $key }}

| Package | Update Version | Impact Score | Issues | Tags   |
|---------|----------------|--------------|--------|--------|
{{- range $value }}
| {{ .PkgRemediationName }} | {{ .Pkg.Insights.PackageCurrentVersion }} | {{ .Score }} | - | {{.Tags}}
{{- end }}
{{ end }}



