# vet 

`vet` is a tool for identifying risks in open source software supply chain. It
helps engineering and security teams to identify potential issues in their open
source dependencies and evaluate them against organizational policies.

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/safedep/vet/badge)](https://api.securityscorecards.dev/projects/github.com/safedep/vet)
[![CodeQL](https://github.com/safedep/vet/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/safedep/vet/actions/workflows/codeql.yml)
[![Scorecard supply-chain security](https://github.com/safedep/vet/actions/workflows/scorecard.yml/badge.svg)](https://github.com/safedep/vet/actions/workflows/scorecard.yml)


## TL;DR

> Ensure `$(go env GOPATH)/bin` is in your `$PATH`

Install using `go get`

```bash
go install github.com/safedep/vet@latest
```

Alternatively, look at [Releases](https://github.com/safedep/vet/releases) for
a pre-built binary for your platform. [SLSA Provenance](https://slsa.dev/provenance/v0.1) is published
along with each binary release.

Get a trial API key for [Insights API](https://safedep.io/docs/concepts/raya-data-platform-overview) access

```bash
vet auth trial --email john.doe@example.com
```

> A time limited trial API key will be sent over email.

Configure `vet` to use API Key to access [Insights API](https://safedep.io/docs/concepts/raya-data-platform-overview)

```bash
vet auth configure
```

> Insights API is used to enrich OSS packages with meta-data for rich query and policy
> decisions

Run `vet` to identify risks

```bash
vet scan -D /path/to/repository
```

or scan a specific (supported) package manifest

```bash
vet scan --lockfiles /path/to/pom.xml
vet scan --lockfiles /path/to/requirements.txt
vet scan --lockfiles /path/to/package-lock.json
```

> Use `vet scan parsers` to list supported package manifest parsers

The default scan uses an opinionated [Summary Reporter](#) which presents
a consolidated summary of findings. Thats NOT about it. Read more for
expression based filtering and policy evaluation.

## Filtering

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

> Use filtering along with `query` command for offline slicing and dicing of
> enriched package manifests. Read [filtering guide](docs/filtering.md)

[Common Expressions Language](https://github.com/google/cel-spec) is used to
evaluate filters on packages. Learn more about [filtering with vet](docs/filtering.md).
Look at [filter input spec](api/filter_input_spec.proto) on attributes
available to the filter expression.

## Policy Evaluation

TODO

## FAQ

### How do I disable the stupid banner?

Set environment variable `VET_DISABLE_BANNER=1`

### Can I use this tool without an API Key for Insight Service?

Probably no. All useful data (enrichments) for a detected package comes from
a backend service. The service is rate limited with quotas to prevent abuse.

Look at `api/insights-v1.yml`. It contains the contract expected for Insights
API. You can perhaps consider rolling out your own to avoid dependency with our
backend.

### Something is wrong! How do I debug this thing?

Run without the eye candy UI and enable log to file or to `stdout`.

Log to `stdout`:

```bash
vet scan -D /path/to/repo -s -l- -v
```

Log to file:

```bash
vet scan -D /path/to/repo -l /tmp/vet.log -v
```

## References

* https://github.com/google/osv-scanner

