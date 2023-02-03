# Vet Report

## Summary

* {{ len .Manifests }} manifest(s) were scanned
* {{ len .AnalyzerEvents }} analyzer event(s) were generated
* {{ len .PolicyEvents }} policy violation(s) were observed

## Details

The scan was performed on following manifests:
{{ range $m := .Manifests }}
* [{{ $m.Ecosystem }}] {{ $m.Path }}
{{ end }}

## Packages

{{ range $m := .Manifests }}
### [{{ $m.Ecosystem }}] {{ $m.Path }}
{{ range $p := $m.Packages }}
#### {{ $p.PackageDetails.Name }} / {{ $p.PackageDetails.Version }}

{{ if and $p.Insights $p.Insights.Vulnerabilities }}
* {{ len *$p.Insights.Vulnerabilites }} vulnerabilities were identified
{{ end }}

{{ end }}
{{ end }}


