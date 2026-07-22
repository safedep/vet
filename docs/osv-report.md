## OSV (OSSF) Report

> [!NOTE]
> The `vet inspect malware` command is deprecated. On-demand malware analysis is moving to a
> JWT-authenticated, payment-sensitive workflow and is no longer available through this API-key
> based command; it will be removed in a future release. The `--report-osv` flow documented
> below depends on it and is deprecated along with it.

Using `--report-osv` we can generate report for `OSSF` malicious package database.

Usage:

```bash
vet inspect malware --purl ... --report-osv .
```

The value of `--report-osv` is the root of [ossf/malicious-packages](https://github.com/ossf/malicious-packages/) repository,
it automatically places the JSON report in correct location, like `osv/malicious/npm/...`.

Flags:

| Flag                       | Usage                               | Default Value                                 |
| -------------------------- | ----------------------------------- | --------------------------------------------- |
| `report-osv-finder-name`   | Name of finder                      | `SafeDep`                                     |
| `report-osv-contacts`      | Contact Info, email, website etc    | `https://safedep.io`                          |
| `report-osv-reference-url` | Report Reference URL, like blog etc | `https://app.safedep.io/community/malysis/ID` |
| `report-osv-with-ranges`   | Use `ranges` affected property      | discrete `versions`                           |
