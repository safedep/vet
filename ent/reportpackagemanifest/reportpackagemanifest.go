// Code generated by ent, DO NOT EDIT.

package reportpackagemanifest

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the reportpackagemanifest type in the database.
	Label = "report_package_manifest"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldManifestID holds the string denoting the manifest_id field in the database.
	FieldManifestID = "manifest_id"
	// FieldSourceType holds the string denoting the source_type field in the database.
	FieldSourceType = "source_type"
	// FieldNamespace holds the string denoting the namespace field in the database.
	FieldNamespace = "namespace"
	// FieldPath holds the string denoting the path field in the database.
	FieldPath = "path"
	// FieldDisplayPath holds the string denoting the display_path field in the database.
	FieldDisplayPath = "display_path"
	// FieldEcosystem holds the string denoting the ecosystem field in the database.
	FieldEcosystem = "ecosystem"
	// FieldCreatedAt holds the string denoting the created_at field in the database.
	FieldCreatedAt = "created_at"
	// FieldUpdatedAt holds the string denoting the updated_at field in the database.
	FieldUpdatedAt = "updated_at"
	// EdgePackages holds the string denoting the packages edge name in mutations.
	EdgePackages = "packages"
	// Table holds the table name of the reportpackagemanifest in the database.
	Table = "report_package_manifests"
	// PackagesTable is the table that holds the packages relation/edge. The primary key declared below.
	PackagesTable = "report_package_manifest_packages"
	// PackagesInverseTable is the table name for the ReportPackage entity.
	// It exists in this package in order to avoid circular dependency with the "reportpackage" package.
	PackagesInverseTable = "report_packages"
)

// Columns holds all SQL columns for reportpackagemanifest fields.
var Columns = []string{
	FieldID,
	FieldManifestID,
	FieldSourceType,
	FieldNamespace,
	FieldPath,
	FieldDisplayPath,
	FieldEcosystem,
	FieldCreatedAt,
	FieldUpdatedAt,
}

var (
	// PackagesPrimaryKey and PackagesColumn2 are the table columns denoting the
	// primary key for the packages relation (M2M).
	PackagesPrimaryKey = []string{"report_package_manifest_id", "report_package_id"}
)

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

var (
	// ManifestIDValidator is a validator for the "manifest_id" field. It is called by the builders before save.
	ManifestIDValidator func(string) error
	// SourceTypeValidator is a validator for the "source_type" field. It is called by the builders before save.
	SourceTypeValidator func(string) error
	// NamespaceValidator is a validator for the "namespace" field. It is called by the builders before save.
	NamespaceValidator func(string) error
	// PathValidator is a validator for the "path" field. It is called by the builders before save.
	PathValidator func(string) error
	// DisplayPathValidator is a validator for the "display_path" field. It is called by the builders before save.
	DisplayPathValidator func(string) error
	// EcosystemValidator is a validator for the "ecosystem" field. It is called by the builders before save.
	EcosystemValidator func(string) error
)

// OrderOption defines the ordering options for the ReportPackageManifest queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByManifestID orders the results by the manifest_id field.
func ByManifestID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldManifestID, opts...).ToFunc()
}

// BySourceType orders the results by the source_type field.
func BySourceType(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldSourceType, opts...).ToFunc()
}

// ByNamespace orders the results by the namespace field.
func ByNamespace(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldNamespace, opts...).ToFunc()
}

// ByPath orders the results by the path field.
func ByPath(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPath, opts...).ToFunc()
}

// ByDisplayPath orders the results by the display_path field.
func ByDisplayPath(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldDisplayPath, opts...).ToFunc()
}

// ByEcosystem orders the results by the ecosystem field.
func ByEcosystem(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldEcosystem, opts...).ToFunc()
}

// ByCreatedAt orders the results by the created_at field.
func ByCreatedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCreatedAt, opts...).ToFunc()
}

// ByUpdatedAt orders the results by the updated_at field.
func ByUpdatedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldUpdatedAt, opts...).ToFunc()
}

// ByPackagesCount orders the results by packages count.
func ByPackagesCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newPackagesStep(), opts...)
	}
}

// ByPackages orders the results by packages terms.
func ByPackages(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newPackagesStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}
func newPackagesStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(PackagesInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2M, false, PackagesTable, PackagesPrimaryKey...),
	)
}
