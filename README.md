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
a pre-built binary for your platform.

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

The default scan uses an opinionated [Console Reporter](#) which presents
a summary of findings per package manifest. Thats NOT about it. Read more for
expression based filtering and policy evaluation.

## Filtering

TODO

## Policy Evaluation

TODO

## FAQ

### How do I disable the stupid banner?

Set environment variable `VET_DISABLE_BANNER=1`

## References

* https://github.com/google/osv-scanner

