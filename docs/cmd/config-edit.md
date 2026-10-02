# vet config edit

Open the user config file in an editor.

## Synopsis

```text
vet config edit [--config FILE]
```

## Description

`vet config edit` opens the user config file, or the `--config` file, in `$VISUAL` or `$EDITOR`, then
checks it as `vet config validate` does. A new file starts with one comment. In agent mode or with
`--no-input`, vet cannot open an editor and exits 2.

## Examples

```text
vet config edit
EDITOR=nano vet config edit
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The file is valid after the edit. |
| 2 | The file is not valid after the edit, or vet cannot open an editor in this mode. |
