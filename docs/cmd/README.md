# Command reference

vet has one page for each command. The table lists every command in the order of the command tree.
`vet <command> --help` prints the same flags.

| Command | Description |
| --- | --- |
| [`vet auth login`](auth-login.md) | Save an API key in the keychain profile. |
| [`vet auth status`](auth-status.md) | Show the credentials that vet uses. |
| [`vet auth logout`](auth-logout.md) | Delete the credentials of the keychain profile. |
| [`vet config show`](config-show.md) | Show the effective config. |
| [`vet config get`](config-get.md) | Print one config value. |
| [`vet config set`](config-set.md) | Set a key in the user config file. |
| [`vet config delete`](config-delete.md) | Remove a key from the user config file. |
| [`vet config edit`](config-edit.md) | Open the user config file in an editor. |
| [`vet config validate`](config-validate.md) | Check a config file. |
| [`vet config schema get`](config-schema-get.md) | Print the JSON Schema of the config file. |
| [`vet doctor`](doctor.md) | Check the state, the config, the credentials and the endpoints. |
| [`vet scan`](scan.md) | Scan a project, a repository, an image, an SBOM or a package. |
| [`vet report show`](report-show.md) | Render a saved report. |
| [`vet report list`](report-list.md) | List the saved scans of the current directory. |
| [`vet report diff`](report-diff.md) | Compare the findings of two saved scans. |
| [`vet report finding show`](report-finding-show.md) | Show one finding of a saved scan. |
| [`vet report capability list`](report-capability-list.md) | List the AI and crypto capabilities of a saved scan. |
| [`vet report schema get`](report-schema-get.md) | Print the JSON Schema of the report. |
| [`vet policy init`](policy-init.md) | Write a starter policy file. |
| [`vet policy validate`](policy-validate.md) | Check a policy file. |
| [`vet policy control list`](policy-control-list.md) | List the controls and their default severities. |
| [`vet policy schema get`](policy-schema-get.md) | Print the JSON Schema of the rule input. |
| [`vet fix github-actions run`](fix-github-actions-run.md) | Pin third-party GitHub Actions to commit SHAs. |
| [`vet endpoint audit`](endpoint-audit.md) | Audit the tools on this machine. |
| [`vet state show`](state-show.md) | Show the state and cache directories, the scans and the retention rules. |
| [`vet state delete`](state-delete.md) | Delete scans or the enrichment cache. |
| [`vet version`](version.md) | Show the version and the build of vet. |

## Global flags

`vet --help` lists the flags that every command takes, such as `-o`, `-v`, `--mode` and `--profile`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command completed. For a scan, the gate passed or no gate was set. |
| 1 | The gate failed. |
| 2 | A usage or config error. The message names the fix. |
| 3 | A runtime error, for example a report file that vet cannot write. |
| 130 | A signal stopped vet. A scan continues on the next run. |
