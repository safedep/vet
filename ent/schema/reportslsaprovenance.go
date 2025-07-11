package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ReportSlsaProvenance holds the schema definition for the ReportSlsaProvenance entity.
type ReportSlsaProvenance struct {
	ent.Schema
}

// Fields of the ReportSlsaProvenance.
func (ReportSlsaProvenance) Fields() []ent.Field {
	return []ent.Field{
		field.String("source_repository").Comment("Source repository URL"),
		field.String("commit_sha").Comment("Git commit SHA"),
		field.String("url").Comment("SLSA provenance URL"),
		field.Bool("verified").Default(false).Comment("Whether the provenance is verified"),
		field.Time("created_at").Optional(),
		field.Time("updated_at").Optional(),
	}
}

// Edges of the ReportSlsaProvenance.
func (ReportSlsaProvenance) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("package", ReportPackage.Type).
			Ref("slsa_provenances").
			Unique(),
	}
}