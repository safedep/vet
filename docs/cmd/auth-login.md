# vet auth login

Save a SafeDep API key and its tenant in the keychain profile.

## Synopsis

```text
vet auth login [--api-key-stdin] [--tenant DOMAIN] [--insecure-keychain-fallback] [--profile NAME]
```

## Description

vet works with no credentials, on the community endpoints. With an API key, vet uses the API
endpoints of your tenant.

`vet auth login` asks for the API key and the tenant domain, and saves them in the OS keychain under
the profile. `--api-key-stdin` reads the key from stdin and `--tenant` gives the tenant, for a
script. In agent mode, with `--no-input` or with no terminal, vet cannot ask: pass both flags, or the
command exits 2 and names the flag.

pmg and the safedep cli read the same keychain profiles. A login on the `default` profile signs in
all three tools.

| Key or flag | Effect |
| --- | --- |
| `--profile NAME`, `cloud.profile` | The keychain profile. `SAFEDEP_PROFILE` sets it when no flag or key does. |
| `--insecure-keychain-fallback`, `cloud.insecure_keychain_fallback` | Use a plaintext file when the machine has no OS keychain. |
| `cloud.keychain_file` | Keep the credentials in this plaintext file and never use the OS keychain. For tests and CI. |

vet takes no token login yet. The safedep cli signs in to the control plane.

## Examples

```text
vet auth login
printf '%s\n' "$KEY" | vet auth login --api-key-stdin --tenant acme.safedep.io
vet --profile work auth login
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet saved the credentials. |
| 2 | A flag is not valid, or vet cannot ask for a value. |
| 3 | vet could not open or write the keychain. |
