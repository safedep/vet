package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// CodeSourceFile holds the schema definition for the CodeSourceFile entity.
type CodeSourceFile struct {
	ent.Schema
}

// Fields of the CodeSourceFile.
func (CodeSourceFile) Fields() []ent.Field {
	return []ent.Field{
		field.String("path").NotEmpty().Unique(),
	}
}

// Edges of the CodeSourceFile.
func (CodeSourceFile) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("deps_usage_evidences", DepsUsageEvidence.Type).
			Ref("used_in"),
	}
}
