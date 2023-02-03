# Filtering

Filter command helps solve the problem of visibility for OSS dependencies in an
application. To support various requirements, we adopt a generic [expressions
language](https://github.com/google/cel-spec) for flexible filtering.

## Input

Filter expressions work on packages (aka. dependencies) and evaluates to
a boolean result. The package is included in the results table if the
expression evaluates to `true`.

Filter expressions get the following input data to work with

| Variable    | Content                                                     |
|-------------|-------------------------------------------------------------|
| `_`         | The root variable, holding other variables                  |
| `vulns`     | Holds a map of vulnerabiliteis by severity                  |
| `scorecard` | Holds OpenSSF scorecard                                     |
| `projects`  | Holds a list of source projects associated with the package |
| `licenses`  | Holds a list of liceses in SPDX license code format         |


## Expressions

Expressions are [CEL](https://github.com/google/cel-spec) statements. While
CEL internals are not required, an [introductory](https://github.com/google/cel-spec/blob/master/doc/intro.md)
knowledge of CEL will help formulating queries.

### Example Queries

| Description                                  | Query                                 |
|----------------------------------------------|---------------------------------------|
| Find packages with a critical vulnerability  | `vulns.critical.exists(x, true)`      |
| Find unmaintained packages as per OpenSSF SC | `scorecard.score["Maintenance"] == 0` |
| Find packages with low stars                 | `projects.exists(x, x.stars < 10)`    |
| Find packages with GPL-2.0 license           | `licenses.exists(x, x == "GPL-2.0")`

Refer to [scorecard checks](https://github.com/ossf/scorecard#checks-1) for
a list of checks available from OpenSSF Scorecards project.

## Query Workflow

Scanning a package manifest is a resource intensive process as it involves
enriching package metadata by queryin [Insights API](https://safedep.io/docs/concepts/raya-data-platform-overview).
However, for filtering and reporting may be done multiple times on the same
manifest. To speed up the process, we can dump the enriched data as JSON and
load the same for filtering and reporting.

Dump enriched JSON manifests to a directory (example)

```bash
vet scan --lockfile /path/to/package-lock.json --json-dump-dir /tmp/dump
vet scan -D /path/to/repository --json-dump-dir /tmp/dump-many
```

Load the enriched metadata for filtering and reporting

```bash
vet query --from /tmp/dump --report-console
vet query --from /tmp/dump --filter 'scorecard.score["Maintenance"] == 0'
```

## FAQ

### How does the filter input JSON look like?

```json
{
  "pkg": {
    "ecosystem": "npm",
    "name": "lodash.camelcase",
    "version": "4.3.0"
  },
  "vulns": {
    "all": [],
    "critical": [],
    "high": [],
    "medium": [],
    "low": []
  },
  "scorecard": {
    "scores": {
      "Binary-Artifacts": 10,
      "Branch-Protection": 0,
      "CII-Best-Practices": 0,
      "Code-Review": 8,
      "Dangerous-Workflow": 10,
      "Dependency-Update-Tool": 0,
      "Fuzzing": 0,
      "License": 10,
      "Maintained": 0,
      "Packaging": -1,
      "Pinned-Dependencies": 9,
      "SAST": 0,
      "Security-Policy": 10,
      "Signed-Releases": -1,
      "Token-Permissions": 0,
      "Vulnerabilities": 10
    }
  },
  "projects": [
    {
      "name": "lodash/lodash",
      "type": "GITHUB",
      "stars": 55518,
      "forks": 6787,
      "issues": 464
    }
  ],
  "licenses": [
    "MIT"
  ]
}
```
