# vet auth status

Show the credentials that vet uses.

## Synopsis

```text
vet auth status [--insecure-keychain-fallback] [--profile NAME] [-o table|plain|json|jsonl]
```

## Description

`vet auth status` shows the profile and where vet found it, the API key and its tenant, and the
cloud access (the control plane token), with the source of each one. With no API key, vet uses the
community endpoints, which have a rate limit. vet reads `SAFEDEP_API_KEY` and `SAFEDEP_TENANT_ID`
first, then the keychain profile.

In a CI job with a workload identity, such as a GitHub Actions job with the permission
`id-token: write`, `SAFEDEP_TENANT_ID` with no `SAFEDEP_API_KEY` selects the workload identity. The
source of the API key is then `workload identity`. `vet auth status` makes no exchange. A scan
exchanges the ID token of the job for a workload credential. The vet GitHub Action sets these
variables from its `tenant-id` and `api-key` inputs. See
[the vet GitHub Action](../github-action.md#safedep-cloud).

vet sends the exchange to `api.safedep.io`, also when `cloud.endpoints.api` names another service
URL. To send it to that service, set `SAFEDEP_CLOUD_DATA_ADDR` to its host and port, such as
`api.example.com:443`.

vet prints no secret. The table shows the last 4 characters of the API key. The JSON output shows no
part of it.

An API key with no tenant, or a tenant with no API key and no workload identity, is a half
credential. vet exits 2 and names the missing value, as `vet scan` does.

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
