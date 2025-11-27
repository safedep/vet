package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ReportScorecardCheck holds the schema definition for the ReportScorecardCheck entity.
type ReportScorecardCheck struct {
	ent.Schema
}

// Fields of the ReportScorecardCheck.
func (ReportScorecardCheck) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").Comment("Name of the scorecard check"),
		field.Float32("score").Comment("Score for this check"),
		field.String("reason").Optional().Comment("Reason for the score"),
		field.Time("created_at").Optional(),
		field.Time("updated_at").Optional(),
	}
}

// Edges of the ReportScorecardCheck.
func (ReportScorecardCheck) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("scorecard", ReportScorecard.Type).
			Ref("checks").
			Unique(),
	}
}
