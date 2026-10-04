# vet config schema get

Print the JSON Schema of the config file.

## Synopsis

```text
vet config schema get [-o json]
```

## Description

`vet config schema get` prints the JSON Schema of the config file, with the options of each built-in
plugin. The section of another plugin stays open, because a third-party plugin can register at run
time. Point a YAML language server at the schema to check `config.yml` in an editor.

## Examples

```text
vet config schema get > vet-config.schema.json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet printed the schema. |
| 2 | A flag is not valid, for example `-o table`. |
