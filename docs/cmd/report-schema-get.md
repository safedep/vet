# vet report schema get

Print the JSON Schema of the report.

## Synopsis

```text
vet report schema get [--line] [-o json]
```

## Description

`vet report schema get` prints the JSON Schema of the report document that `-o json` writes: the
header, the records and the trailer. vet generates the schema from its Go types, so the schema and
the report cannot drift apart. The report carries `schema_version`.

`--line` prints the schema of one line of `-o jsonl`: the header, one record or the trailer. Each
line names that schema in its `$schema` field. A minor schema version can add fields, so a reader must
accept a field that it does not know.

## Examples

```text
vet report schema get > vet-report.schema.json
vet report schema get --line > vet-report-line.schema.json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet printed the schema. |
| 2 | A flag is not valid, for example `-o table`. |
