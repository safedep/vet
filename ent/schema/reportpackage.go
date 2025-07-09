package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ReportPackage holds the schema definition for the ReportPackage entity.
type ReportPackage struct {
	ent.Schema
}

// Fields of the ReportPackage.
func (ReportPackage) Fields() []ent.Field {
	return []ent.Field{
		field.String("package_id").NotEmpty().Unique(),
		field.String("name").NotEmpty(),
		field.String("version").NotEmpty(),
		field.String("ecosystem").NotEmpty(),
		field.String("package_url").NotEmpty(),
		field.Int("depth").Default(0),
		field.Bool("is_direct").Default(false),
		field.Bool("is_malware").Default(false),
		field.Bool("is_suspicious").Default(false),
		field.JSON("package_details", map[string]interface{}{}).Optional(),
		field.JSON("insights_v2", map[string]interface{}{}).Optional(),
		field.JSON("code_analysis", map[string]interface{}{}).Optional(),
		field.Time("created_at").Optional(),
		field.Time("updated_at").Optional(),
	}
}

// Edges of the ReportPackage.
func (ReportPackage) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("manifests", ReportPackageManifest.Type).
			Ref("packages"),
		edge.To("vulnerabilities", ReportVulnerability.Type).
			Annotations(entsql.Annotation{
				OnDelete: entsql.Cascade,
			}),
		edge.To("licenses", ReportLicense.Type).
			Annotations(entsql.Annotation{
				OnDelete: entsql.Cascade,
			}),
		edge.To("dependencies", ReportDependency.Type).
			Annotations(entsql.Annotation{
				OnDelete: entsql.Cascade,
			}),
		edge.To("malware_analysis", ReportMalware.Type).
			Unique().
			Annotations(entsql.Annotation{
				OnDelete: entsql.Cascade,
			}),
		edge.To("projects", ReportProject.Type).
			Annotations(entsql.Annotation{
				OnDelete: entsql.Cascade,
			}),
		edge.To("slsa_provenances", ReportSlsaProvenance.Type).
			Annotations(entsql.Annotation{
				OnDelete: entsql.Cascade,
			}),
	}
}
