## OSV (OSSF) Report

Using `--report-osv` we can generate report for `OSSF` malicious package database. 

Usage:

```bash
vet inspect malware --purl ... --report-osv .
```

The value of `--report-osv` is the root of [ossf/malicious-packages](https://github.com/ossf/malicious-packages/) repository, 
it automatically places the JSON report in correct location, like `osv/malicious/npm/...`.

Flags:

| Flag                       | Usage                                 | Default Value                                      |
|----------------------------|---------------------------------------|----------------------------------------------------|
| `report-osv-finder-name`   | Name of finder                        | `SafeDep`                                          |
| `report-osv-contacts`      | Contact Info, email, website etc      | `https://safedep.io`                               |
| `report-osv-reference-url` | Report Reference URL, like blog etc   | `https://platform.safedep.io/community/malysis/ID` |
| `report-osv-with-ranges`        | Use `ranges` affected property | discrete `versions`                                |
