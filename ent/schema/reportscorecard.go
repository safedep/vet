package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ReportScorecard holds the schema definition for the ReportScorecard entity.
type ReportScorecard struct {
	ent.Schema
}

// Fields of the ReportScorecard.
func (ReportScorecard) Fields() []ent.Field {
	return []ent.Field{
		field.Float32("score").Comment("Overall scorecard score"),
		field.String("scorecard_version").Comment("Version of the scorecard tool used"),
		field.String("repo_name").Comment("Repository name"),
		field.String("repo_commit").Comment("Repository commit SHA"),
		field.String("date").Optional().Comment("Date published by OpenSSF scorecard"),
		field.Time("created_at").Optional(),
		field.Time("updated_at").Optional(),
	}
}

// Edges of the ReportScorecard.
func (ReportScorecard) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("project", ReportProject.Type).
			Ref("scorecard").
			Unique(),
		edge.To("checks", ReportScorecardCheck.Type).
			Annotations(entsql.Annotation{
				OnDelete: entsql.Cascade,
			}),
	}
}
