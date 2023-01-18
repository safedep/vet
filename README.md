# vet 
Tool for identifying open source software supply chain risks

## TL;DR

Build this repository

> Ensure `$(go env GOPATH)/bin` is in your `$PATH`

```bash
make oapi-codegen-install && make
```

Alternatively install using

```bash
go install github.com/safedep/vet@latest
```

Configure `vet` to use API Key to access [Insights API](#)

```bash
vet auth configure
```

> Alternatively pass the API key as environment to skip configuration

Run `vet` to identify risks

```bash
vet scan
```

## Usage

### Configuration

Insights API Key can be passed at runtime using environment variable

```bash
VET_INSIGHTS_API_KEY=... vet scan
```

## FAQ

### How do I disable the stupid banner?

Set environment variable `VET_DISABLE_BANNER=1`
