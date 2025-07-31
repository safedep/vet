package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ReportDependency holds the schema definition for the ReportDependency entity.
type ReportDependency struct {
	ent.Schema
}

// Fields of the ReportDependency.
func (ReportDependency) Fields() []ent.Field {
	return []ent.Field{
		field.String("dependency_package_id").NotEmpty(),
		field.String("dependency_name").NotEmpty(),
		field.String("dependency_version").NotEmpty(),
		field.String("dependency_ecosystem").NotEmpty(),
		field.String("dependency_type").Optional(),
		field.Int("depth").Default(0),
		field.Time("created_at").Optional(),
		field.Time("updated_at").Optional(),
	}
}

// Edges of the ReportDependency.
func (ReportDependency) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("package", ReportPackage.Type).
			Ref("dependencies").
			Unique(),
	}
}
