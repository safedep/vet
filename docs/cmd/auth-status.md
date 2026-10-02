# vet auth status

Show the credentials that vet uses.

## Synopsis

```text
vet auth status [--insecure-keychain-fallback] [--profile NAME] [-o table|plain|json|jsonl]
```

## Description

`vet auth status` shows the profile and where vet found it, the tenant, the source of the data plane
API key and the source of the control plane token. vet reads `SAFEDEP_API_KEY` and
`SAFEDEP_TENANT_ID` first, then the keychain profile.

vet prints no secret. The table shows the last 4 characters of the API key. The JSON output shows no
part of it.

An API key with no tenant, or a tenant with no API key, is a half credential. vet exits 2 and names
the missing value, as `vet scan` does.

## Examples

```text
vet auth status
vet --profile work auth status -o json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet showed the credentials, or that there are none. |
| 2 | The credentials are half set, or a flag is not valid. |
| 3 | vet could not read the keychain. |
