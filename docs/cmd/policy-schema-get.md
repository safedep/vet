# vet policy schema get

Print the JSON Schema of the rule input.

## Synopsis

```text
vet policy schema get [-o json]
```

## Description

`vet policy schema get` prints the JSON Schema of the variables that a policy rule reads: `finding`,
`package` and `manifest`. vet generates it from its Go types. An optional field with no value, such
as `package.days_since_publish` of a package with no publish date, is absent. A rule that reads an
absent field does not match. `has()` tests a field, for example `has(package.days_since_publish)`.

## Examples

```text
vet policy schema get > vet-policy-input.schema.json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet printed the schema. |
| 2 | A flag is not valid, for example `-o table`. |
