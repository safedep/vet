package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// ReportDependencyGraph holds the schema definition for the ReportDependencyGraph entity.
// This represents the dependency graph with edges between packages, allowing for
// complex dependency analysis including path tracing and dependent discovery.
type ReportDependencyGraph struct {
	ent.Schema
}

// Fields of the ReportDependencyGraph.
func (ReportDependencyGraph) Fields() []ent.Field {
	return []ent.Field{
		// Source package (dependent) - using package_id string field for reference
		field.String("from_package_id").NotEmpty().Comment("Reference to ReportPackage.package_id"),
		field.String("from_package_name").NotEmpty(),
		field.String("from_package_version").NotEmpty(),
		field.String("from_package_ecosystem").NotEmpty(),

		// Target package (dependency) - using package_id string field for reference
		field.String("to_package_id").NotEmpty().Comment("Reference to ReportPackage.package_id"),
		field.String("to_package_name").NotEmpty(),
		field.String("to_package_version").NotEmpty(),
		field.String("to_package_ecosystem").NotEmpty(),

		// Edge metadata
		field.String("dependency_type").Optional().Comment("e.g., runtime, dev, optional"),
		field.String("version_constraint").Optional().Comment("e.g., ^1.2.3, >=2.0.0"),
		field.Int("depth").Default(0).Comment("Depth in dependency tree"),
		field.Bool("is_direct").Default(false).Comment("Direct dependency from manifest"),
		field.Bool("is_root_edge").Default(false).Comment("Edge from root package"),

		// Manifest context
		field.String("manifest_id").NotEmpty().Comment("Manifest where this edge was discovered"),

		// Metadata
		field.Time("created_at").Optional(),
		field.Time("updated_at").Optional(),
	}
}

// Edges of the ReportDependencyGraph.
func (ReportDependencyGraph) Edges() []ent.Edge {
	return []ent.Edge{
		// Note: We're not using direct foreign key edges here since we need to reference
		// packages by their package_id field, not the auto-generated ID.
		// The relationships will be managed through the package_id fields and queries.
	}
}

// Indexes of the ReportDependencyGraph for efficient querying.
func (ReportDependencyGraph) Indexes() []ent.Index {
	return []ent.Index{
		// Index for finding all dependencies of a package
		index.Fields("from_package_id"),

		// Index for finding all dependents of a package
		index.Fields("to_package_id"),

		// Index for finding edges by manifest
		index.Fields("manifest_id"),

		// Index for finding direct dependencies
		index.Fields("from_package_id", "is_direct"),

		// Index for finding root edges
		index.Fields("is_root_edge"),

		// Composite index for efficient path queries
		index.Fields("from_package_id", "to_package_id", "manifest_id"),

		// Index for dependency type filtering
		index.Fields("dependency_type"),

		// Index for depth-based queries
		index.Fields("depth"),
	}
}
