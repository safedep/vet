package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// DepsUsageEvidence holds the schema definition for the DepsUsageEvidence entity.
type DepsUsageEvidence struct {
	ent.Schema
}

// Fields of the DepsUsageEvidence.
func (DepsUsageEvidence) Fields() []ent.Field {
	return []ent.Field{
		field.String("package_hint").Optional().Nillable(),
		field.String("module_name"),
		field.String("module_item").Optional().Nillable(),
		field.String("module_alias").Optional().Nillable(),
		field.Bool("is_wild_card_usage").Optional().Default(false),
		field.String("identifier").Optional().Nillable(),
		field.String("usage_file_path"),
		field.Uint("line"),
	}
}

// Edges of the DepsUsageEvidence.
func (DepsUsageEvidence) Edges() []ent.Edge {
	return []ent.Edge{
		edge.
			To("used_in", CodeSourceFile.Type).
			Unique().
			Required(),
	}
}
