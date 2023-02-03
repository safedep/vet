# vet 

`vet` is a tool for identifying risks in open source software supply chain. It
helps engineering and security teams to identify potential issues in their open
source dependencies and evaluate them against organizational policies.

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

The default scan uses an opinionated [Console Reporter](#) which presents
a summary of findings per package manifest. Thats NOT about it. Read more for
expression based filtering and policy evaluation.

## Filtering

Find dependencies that seems not very popular

```bash
vet scan --lockfiles /path/to/pom.xml --report-console=false \
    --filter='projects.exists(x, x.stars < 10)'
```

Find dependencies with a critical vulnerability

```bash
vet scan --lockfiles /path/to/pom.xml --report-console=false \
    --filter='vulns.critical.exists_one(x, true)'
```

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

Look at `api/insights_api.yml`. It contains the contract expected for Insights
API. You can perhaps consider rolling out your own to avoid dependency with our
backend.

## References

* https://github.com/google/osv-scanner

