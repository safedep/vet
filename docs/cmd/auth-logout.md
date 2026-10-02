# vet auth logout

Delete the credentials of the keychain profile.

## Synopsis

```text
vet auth logout [--insecure-keychain-fallback] [--profile NAME]
```

## Description

`vet auth logout` deletes the API key, the tenant and the token of the profile. pmg and the safedep
cli read the same profile, so they sign out too. vet tells you which tools share the profile.

`SAFEDEP_API_KEY` and `SAFEDEP_TENANT_ID` still apply after a logout. vet warns when
`SAFEDEP_API_KEY` is set.

## Examples

```text
vet auth logout
vet --profile work auth logout
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet deleted the credentials. |
| 3 | vet could not open or write the keychain. |
