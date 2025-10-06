# Policy Engine Development

The policy engine is implemented using [Common Expressions Languages](https://cel.dev).
This development document is ONLY for Policy v2, internally represented
as Filter V2 for naming consistency.

## Enum Constants

Protobuf enums are exposed as integer values in CEL. To improve policy readability, we generate enum constant maps that allow using symbolic names instead of integers.

**Example usage in policies:**

```cel
// Instead of: p.project.type == 1
p.project.type == ProjectSourceType.GITHUB

// Instead of: pkg.ecosystem == 2
pkg.ecosystem == Ecosystem.NPM
```

**How it works:**

- `pkg/analyzer/filterv2/enums.go` registers enums via `RegisteredEnums` by referencing protobuf-generated `Type_value` maps
- `pkg/analyzer/filterv2/enumgen/` generates `enums_generated.go` with constant maps
- Run `go generate ./pkg/analyzer/filterv2/` to regenerate after adding new enums

**Adding new enums:**

1. Add entry to `RegisteredEnums` in `pkg/analyzer/filterv2/enums.go`:

   ```go
   {
       Name:     "SeverityRisk",
       Prefix:   "RISK_",
       ValueMap: vulnerabilityv1.Severity_Risk_value,
   }
   ```

2. Declare the enum variable in `pkg/analyzer/filterv2/eval.go` `NewEvaluator()`:

   ```go
   cel.Variable("SeverityRisk", cel.MapType(cel.StringType, cel.IntType))
   ```

3. Run `go generate ./pkg/analyzer/filterv2/`

The generator automatically strips prefixes (e.g., `RISK_CRITICAL` → `CRITICAL`) and keeps enums synchronized with protobuf definitions.
