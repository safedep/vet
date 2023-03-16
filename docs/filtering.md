# Filtering

Filter command helps solve the problem of visibility for OSS dependencies in an
application. To support various requirements, we adopt a generic [expressions
language](https://github.com/google/cel-spec) for flexible filtering.

## Example

```bash
vet scan -D /path/to/repo \
    --report-summary=false \
    --filter 'licenses.exists(p, p == "MIT")'
```

The scan will list only packages that use the `MIT` license.

Find dependencies that seems not very popular

```bash
vet scan --lockfiles /path/to/pom.xml --report-summary=false \
    --filter='projects.exists(x, x.stars < 10)'
```

Find dependencies with a critical vulnerability

```bash
vet scan --lockfiles /path/to/pom.xml --report-summary=false \
    --filter='vulns.critical.exists_one(x, true)'
```

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


Refer to [filter input spec](../api/filter_input_spec.proto) for detailed
structure of input messages.

## Expressions

Expressions are [CEL](https://github.com/google/cel-spec) statements. While
CEL internals are not required, an [introductory](https://github.com/google/cel-spec/blob/master/doc/intro.md)
knowledge of CEL will help formulating queries. Expressions are logical
statements that evaluate to `true` or `false`.

### Example Queries

| Description                                  | Query                                |
|----------------------------------------------|--------------------------------------|
| Find packages with a critical vulnerability  | `vulns.critical.exists(x, true)`     |
| Find unmaintained packages as per OpenSSF SC | `scorecard.scores.Maintained == 0`   |
| Find packages with low stars                 | `projects.exists(x, x.stars < 10)`   |
| Find packages with GPL-2.0 license           | `licenses.exists(x, x == "GPL-2.0")`

Refer to [scorecard checks](https://github.com/ossf/scorecard#checks-1) for
a list of checks available from OpenSSF Scorecards project.

## Query Workflow

Scanning a package manifest is a resource intensive process as it involves
enriching package metadata by queryin [Insights API](https://safedep.io/docs/concepts/raya-data-platform-overview).
However, filtering and reporting may be done multiple times on the same
manifest. To speed up the process, we can dump the enriched data as JSON and
load the same for filtering and reporting.

Dump enriched JSON manifests to a directory (example)

```bash
vet scan --lockfile /path/to/package-lock.json --json-dump-dir /tmp/dump
vet scan -D /path/to/repository --json-dump-dir /tmp/dump-many
```

Load the enriched metadata for filtering and reporting

```bash
vet query --from /tmp/dump --report-summary
vet query --from /tmp/dump --filter 'scorecard.score.Maintained == 0'
```

## Security Gating with Filters

A simple security gate (in CI) can be achieved using the filters. The
`--filter-fail` argument tells the `Filter Analyzer` module to fail the command
if any package matches the given filter.

Example:

```bash
vet query --from /path/to/json-dump \
    --filter 'scorecard.scores.Maintained == 0' \
    --filter-fail
```

Subsequently, the command fails with `-1` exit code in case of match

```bash
➜  vet git:(develop) ✗ echo $?
255
```

## Filter Suite

A single filter is useful for identification of packages that meet some
specific criteria. While it helps solve various use-cases, it is not entirely
suitable for `security gating` where multiple filters may be required to
express an organization's acceptable OSS usage policy.

For example, an organization may define a filter to deny certain type of
packages:

1. Any package that has a high or critical vulnerability
2. Any package that does not match acceptable OSS licenses
3. Any package that has a low [OpenSSF scorecard score](https://github.com/ossf/scorecard)

To express this policy, multiple filters are needed such as:

```
vulns.critical.exists(p, true) ||
licenses.exists(p, (p != "MIT") && (p != "Apache-2.0")) ||
(scorecard.scores.Maintained == 0)
```

To solve this problem, we introduce the concept of `Filter Suite`. It can be
represented as an YAML file containing multiple filters to match:

```yaml
name: Generic Filter Suite
description: Example filter suite with canned filters
filters:
  - name: critical-vuln
    value: |
      vulns.critical.exists(p, true)
  - name: safe-licenses
    value: |
      licenses.exists(p, (p != "MIT") && (p != "Apache-2.0"))
  - name: ossf-maintained
    value: |
      scorecard.scores.Maintained == 0
```

A scan or query operation can be invoked using the filter suite:

```bash
vet scan -D /path/to/repo --filter-suite /path/to/filters.yml --filter-fail
```

The filter suite will be evaluated as:

* Ordered list of filters as given in the suite file
* Stop on first rule match for a given package

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
