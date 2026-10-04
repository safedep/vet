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

`package.name` and `package.version` hold the canonical form under the rule of the ecosystem.
`package.raw_name` and `package.raw_version` hold the form that the manifest writes. A rule has two
functions that apply the rule of the ecosystem:

- `package.is("name")` is true when the name names the package. `package.is("python-dateutil")`
  matches the PyPI package `python.dateutil`. Compare names with it, not with `==`.
- `package.version_cmp("1.2.3")` gives -1, 0 or 1 when the version of the package is below, equal
  to or above `1.2.3`. An ecosystem with no version order, such as GitHub Actions, gives no answer.
  A condition that needs the answer does not match, as with an absent field. CEL still decides
  `a || b` when `b` is true, so a rule can add another check for the packages with no order.

## Examples

```text
vet policy schema get > vet-policy-input.schema.json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet printed the schema. |
| 2 | A flag is not valid, for example `-o table`. |
