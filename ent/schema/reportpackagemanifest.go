package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ReportPackageManifest holds the schema definition for the ReportPackageManifest entity.
type ReportPackageManifest struct {
	ent.Schema
}

// Fields of the ReportPackageManifest.
func (ReportPackageManifest) Fields() []ent.Field {
	return []ent.Field{
		field.String("manifest_id").NotEmpty().Unique(),
		field.String("source_type").NotEmpty(),
		field.String("namespace").NotEmpty(),
		field.String("path").NotEmpty(),
		field.String("display_path").NotEmpty(),
		field.String("ecosystem").NotEmpty(),
		field.Time("created_at").Optional(),
		field.Time("updated_at").Optional(),
	}
}

// Edges of the ReportPackageManifest.
func (ReportPackageManifest) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("packages", ReportPackage.Type),
	}
}
