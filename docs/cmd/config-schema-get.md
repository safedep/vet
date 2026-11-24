# vet config schema get

Print the JSON Schema of the config file.

## Synopsis

```text
vet config schema get [-o json]
```

## Description

`vet config schema get` prints the JSON Schema of the config file. It describes each built-in plugin
and its options. A plugin with a switch has the key `enabled`, with its default. A report format has
no `enabled` key, because `-o` and `--report` select it. The schema has no other plugin. Point a YAML
language server at the schema to check `config.yml` in an editor.

## Examples

```text
vet config schema get > vet-config.schema.json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet printed the schema. |
| 2 | A flag is not valid, for example `-o table`. |
