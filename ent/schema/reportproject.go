package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// ReportProject holds the schema definition for the ReportProject entity.
type ReportProject struct {
	ent.Schema
}

// Fields of the ReportProject.
func (ReportProject) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").NotEmpty(),
		field.String("url").Optional(),
		field.String("description").Optional(),
		field.Int32("stars").Optional(),
		field.Int32("forks").Optional(),
		field.JSON("scorecard", map[string]interface{}{}).Optional(),
		field.Time("created_at").Optional(),
		field.Time("updated_at").Optional(),
	}
}

// Edges of the ReportProject.
func (ReportProject) Edges() []ent.Edge {
	return []ent.Edge{}
}
