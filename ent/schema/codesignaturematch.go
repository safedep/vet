package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// CodeSignatureMatch holds the schema definition for the CodeSignatureMatch entity.
type CodeSignatureMatch struct {
	ent.Schema
}

// Fields of the CodeSignatureMatch.
func (CodeSignatureMatch) Fields() []ent.Field {
	return []ent.Field{
		field.String("signature_id").NotEmpty(),
		field.String("signature_vendor").Optional(),
		field.String("signature_product").Optional(),
		field.String("signature_service").Optional(),
		field.String("signature_description").Optional(),
		field.JSON("tags", []string{}).Optional(),
		field.String("file_path").NotEmpty(),
		field.String("language").NotEmpty(),
		field.Uint("line").Optional(),
		field.Uint("column").Optional(),
		field.String("callee_namespace").Optional(),
		field.String("matched_call").Optional(),
		field.String("package_hint").Optional().Nillable(),
	}
}

// Edges of the CodeSignatureMatch.
func (CodeSignatureMatch) Edges() []ent.Edge {
	return []ent.Edge{
		edge.
			To("source_file", CodeSourceFile.Type).
			Unique().
			Required(),
	}
}
