// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/safedep/vet/ent/reportpackagemanifest"
)

// ReportPackageManifest is the model entity for the ReportPackageManifest schema.
type ReportPackageManifest struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// ManifestID holds the value of the "manifest_id" field.
	ManifestID string `json:"manifest_id,omitempty"`
	// SourceType holds the value of the "source_type" field.
	SourceType string `json:"source_type,omitempty"`
	// Namespace holds the value of the "namespace" field.
	Namespace string `json:"namespace,omitempty"`
	// Path holds the value of the "path" field.
	Path string `json:"path,omitempty"`
	// DisplayPath holds the value of the "display_path" field.
	DisplayPath string `json:"display_path,omitempty"`
	// Ecosystem holds the value of the "ecosystem" field.
	Ecosystem string `json:"ecosystem,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// UpdatedAt holds the value of the "updated_at" field.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the ReportPackageManifestQuery when eager-loading is set.
	Edges        ReportPackageManifestEdges `json:"edges"`
	selectValues sql.SelectValues
}

// ReportPackageManifestEdges holds the relations/edges for other nodes in the graph.
type ReportPackageManifestEdges struct {
	// Packages holds the value of the packages edge.
	Packages []*ReportPackage `json:"packages,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// PackagesOrErr returns the Packages value or an error if the edge
// was not loaded in eager-loading.
func (e ReportPackageManifestEdges) PackagesOrErr() ([]*ReportPackage, error) {
	if e.loadedTypes[0] {
		return e.Packages, nil
	}
	return nil, &NotLoadedError{edge: "packages"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*ReportPackageManifest) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case reportpackagemanifest.FieldID:
			values[i] = new(sql.NullInt64)
		case reportpackagemanifest.FieldManifestID, reportpackagemanifest.FieldSourceType, reportpackagemanifest.FieldNamespace, reportpackagemanifest.FieldPath, reportpackagemanifest.FieldDisplayPath, reportpackagemanifest.FieldEcosystem:
			values[i] = new(sql.NullString)
		case reportpackagemanifest.FieldCreatedAt, reportpackagemanifest.FieldUpdatedAt:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the ReportPackageManifest fields.
func (rpm *ReportPackageManifest) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case reportpackagemanifest.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			rpm.ID = int(value.Int64)
		case reportpackagemanifest.FieldManifestID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field manifest_id", values[i])
			} else if value.Valid {
				rpm.ManifestID = value.String
			}
		case reportpackagemanifest.FieldSourceType:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field source_type", values[i])
			} else if value.Valid {
				rpm.SourceType = value.String
			}
		case reportpackagemanifest.FieldNamespace:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field namespace", values[i])
			} else if value.Valid {
				rpm.Namespace = value.String
			}
		case reportpackagemanifest.FieldPath:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field path", values[i])
			} else if value.Valid {
				rpm.Path = value.String
			}
		case reportpackagemanifest.FieldDisplayPath:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field display_path", values[i])
			} else if value.Valid {
				rpm.DisplayPath = value.String
			}
		case reportpackagemanifest.FieldEcosystem:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field ecosystem", values[i])
			} else if value.Valid {
				rpm.Ecosystem = value.String
			}
		case reportpackagemanifest.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				rpm.CreatedAt = value.Time
			}
		case reportpackagemanifest.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				rpm.UpdatedAt = value.Time
			}
		default:
			rpm.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the ReportPackageManifest.
// This includes values selected through modifiers, order, etc.
func (rpm *ReportPackageManifest) Value(name string) (ent.Value, error) {
	return rpm.selectValues.Get(name)
}

// QueryPackages queries the "packages" edge of the ReportPackageManifest entity.
func (rpm *ReportPackageManifest) QueryPackages() *ReportPackageQuery {
	return NewReportPackageManifestClient(rpm.config).QueryPackages(rpm)
}

// Update returns a builder for updating this ReportPackageManifest.
// Note that you need to call ReportPackageManifest.Unwrap() before calling this method if this ReportPackageManifest
// was returned from a transaction, and the transaction was committed or rolled back.
func (rpm *ReportPackageManifest) Update() *ReportPackageManifestUpdateOne {
	return NewReportPackageManifestClient(rpm.config).UpdateOne(rpm)
}

// Unwrap unwraps the ReportPackageManifest entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (rpm *ReportPackageManifest) Unwrap() *ReportPackageManifest {
	_tx, ok := rpm.config.driver.(*txDriver)
	if !ok {
		panic("ent: ReportPackageManifest is not a transactional entity")
	}
	rpm.config.driver = _tx.drv
	return rpm
}

// String implements the fmt.Stringer.
func (rpm *ReportPackageManifest) String() string {
	var builder strings.Builder
	builder.WriteString("ReportPackageManifest(")
	builder.WriteString(fmt.Sprintf("id=%v, ", rpm.ID))
	builder.WriteString("manifest_id=")
	builder.WriteString(rpm.ManifestID)
	builder.WriteString(", ")
	builder.WriteString("source_type=")
	builder.WriteString(rpm.SourceType)
	builder.WriteString(", ")
	builder.WriteString("namespace=")
	builder.WriteString(rpm.Namespace)
	builder.WriteString(", ")
	builder.WriteString("path=")
	builder.WriteString(rpm.Path)
	builder.WriteString(", ")
	builder.WriteString("display_path=")
	builder.WriteString(rpm.DisplayPath)
	builder.WriteString(", ")
	builder.WriteString("ecosystem=")
	builder.WriteString(rpm.Ecosystem)
	builder.WriteString(", ")
	builder.WriteString("created_at=")
	builder.WriteString(rpm.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("updated_at=")
	builder.WriteString(rpm.UpdatedAt.Format(time.ANSIC))
	builder.WriteByte(')')
	return builder.String()
}

// ReportPackageManifests is a parsable slice of ReportPackageManifest.
type ReportPackageManifests []*ReportPackageManifest
