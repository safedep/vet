# Evasion corpus

The evasion corpus measures how the attack detections of vet hold up when an attacker changes the
shape of an attack. Each case is a small synthetic repository. `TestEvasionCorpus` scans each case
with the built-in extractors and controls, and with no enricher and no network. It writes the result
to [coverage.md](coverage.md).

```bash
go test ./test/evasion/ -count=1                  # check the cases and the table
UPDATE_GOLDEN=1 go test ./test/evasion/ -count=1  # rewrite coverage.md
```

## Rules for a case

- Copy only the shape of an attack: the file name, the position, the padding, the encoding and the
  spelling. Never download, clone, paste or run a real sample.
- Keep each file name inside the case folder. The test rejects `../` and absolute paths.
- Each URL is `https://x.example/...`. Each payload is harmless, such as `console.log(1)` or the
  `{% loader %}` of the runner.
- Add near misses too. A near miss is a clean file that looks like the attack, such as a config that
  aligns a comment after a run of spaces. It keeps a detection from growing into false positives.

## Case format

A case is a `txtar` file under `cases/<group>/`. The comment section holds:

| Line | Meaning |
| --- | --- |
| `# <summary>` | One line that says what the case does. The table shows it. |
| `want: <ids>` | The exact control ids that the scan must give, or `none`. |
| `miss: <reason>` | Optional. The detections do not catch the case yet, and this is why. Name the issue that fixes it. |
| `have: <ids>` | Only with `miss`. The control ids that the scan gives today, or `none`. |
| `source: endpoint` | Optional. `vet endpoint audit` reads the case, with the files under the home folder. |

```
# A loader after 280 no-break spaces
want: padded-code
-- postcss.config.mjs --
export default config;{% repeat "\u00a0" 280 %}{% loader %}
```

A file body is a Go template with the delimiters `{%` and `%}`. It writes the bytes that a reader
cannot see or type. Write each invisible character and each raw byte as an escape. The test rejects a
case file that holds one, or that is not valid UTF-8, because a reviewer cannot see it.

| Template | Writes |
| --- | --- |
| `{% "\u200b\x00" %}` | A Go string constant, with any escape |
| `{% repeat " " 280 %}` | A string 280 times |
| `{% loader %}` | A synthetic obfuscated loader that runs nothing |
| `{% selectors "text" %}` | The text in variation selectors, one byte in each |
| `{% tags "text" %}` | The text in Unicode tag characters |
| `{% range $c := chars "text" %}...{% end %}` | One step for each character |

## A miss and a hard assertion

A case with no `miss` line is a hard assertion: the test fails when the scan gives other findings.
A known miss is a hard assertion on its `have` line. So a change that takes a finding away from a
known miss fails the test too. When a detection starts to catch a known miss, the test fails until
you remove the `miss` and `have` lines. So the table always matches the code.

A pull request that changes a detection commits the `coverage.md` diff. The diff shows the cases that
the change catches and the cases that it loses.

## From a report to a case

When a user reports an attack that vet misses, write the shape of the report as a case with `miss`
and `have` lines. Add it to the group of the technique, or start a group. Link the issue that fixes
it in the reason.
