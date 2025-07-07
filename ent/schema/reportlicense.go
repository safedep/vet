package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ReportLicense holds the schema definition for the ReportLicense entity.
type ReportLicense struct {
	ent.Schema
}

// Fields of the ReportLicense.
func (ReportLicense) Fields() []ent.Field {
	return []ent.Field{
		field.String("license_id").NotEmpty(),
		field.String("name").Optional(),
		field.String("spdx_id").Optional(),
		field.String("url").Optional(),
		field.Bool("is_osi_approved").Optional(),
		field.Bool("is_fsf_approved").Optional(),
		field.Bool("is_saas_compatible").Optional(),
		field.Bool("is_commercial_use_allowed").Optional(),
		field.Time("created_at").Optional(),
		field.Time("updated_at").Optional(),
	}
}

// Edges of the ReportLicense.
func (ReportLicense) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("package", ReportPackage.Type).
			Ref("licenses").
			Unique(),
	}
}
