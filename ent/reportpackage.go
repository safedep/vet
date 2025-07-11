// Code generated by ent, DO NOT EDIT.

package ent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/safedep/vet/ent/reportmalware"
	"github.com/safedep/vet/ent/reportpackage"
)

// ReportPackage is the model entity for the ReportPackage schema.
type ReportPackage struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// PackageID holds the value of the "package_id" field.
	PackageID string `json:"package_id,omitempty"`
	// Name holds the value of the "name" field.
	Name string `json:"name,omitempty"`
	// Version holds the value of the "version" field.
	Version string `json:"version,omitempty"`
	// Ecosystem holds the value of the "ecosystem" field.
	Ecosystem string `json:"ecosystem,omitempty"`
	// PackageURL holds the value of the "package_url" field.
	PackageURL string `json:"package_url,omitempty"`
	// Depth holds the value of the "depth" field.
	Depth int `json:"depth,omitempty"`
	// IsDirect holds the value of the "is_direct" field.
	IsDirect bool `json:"is_direct,omitempty"`
	// IsMalware holds the value of the "is_malware" field.
	IsMalware bool `json:"is_malware,omitempty"`
	// IsSuspicious holds the value of the "is_suspicious" field.
	IsSuspicious bool `json:"is_suspicious,omitempty"`
	// PackageDetails holds the value of the "package_details" field.
	PackageDetails map[string]interface{} `json:"package_details,omitempty"`
	// InsightsV2 holds the value of the "insights_v2" field.
	InsightsV2 map[string]interface{} `json:"insights_v2,omitempty"`
	// CodeAnalysis holds the value of the "code_analysis" field.
	CodeAnalysis map[string]interface{} `json:"code_analysis,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// UpdatedAt holds the value of the "updated_at" field.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the ReportPackageQuery when eager-loading is set.
	Edges        ReportPackageEdges `json:"edges"`
	selectValues sql.SelectValues
}

// ReportPackageEdges holds the relations/edges for other nodes in the graph.
type ReportPackageEdges struct {
	// Manifests holds the value of the manifests edge.
	Manifests []*ReportPackageManifest `json:"manifests,omitempty"`
	// Vulnerabilities holds the value of the vulnerabilities edge.
	Vulnerabilities []*ReportVulnerability `json:"vulnerabilities,omitempty"`
	// Licenses holds the value of the licenses edge.
	Licenses []*ReportLicense `json:"licenses,omitempty"`
	// Dependencies holds the value of the dependencies edge.
	Dependencies []*ReportDependency `json:"dependencies,omitempty"`
	// MalwareAnalysis holds the value of the malware_analysis edge.
	MalwareAnalysis *ReportMalware `json:"malware_analysis,omitempty"`
	// Projects holds the value of the projects edge.
	Projects []*ReportProject `json:"projects,omitempty"`
	// SlsaProvenances holds the value of the slsa_provenances edge.
	SlsaProvenances []*ReportSlsaProvenance `json:"slsa_provenances,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [7]bool
}

// ManifestsOrErr returns the Manifests value or an error if the edge
// was not loaded in eager-loading.
func (e ReportPackageEdges) ManifestsOrErr() ([]*ReportPackageManifest, error) {
	if e.loadedTypes[0] {
		return e.Manifests, nil
	}
	return nil, &NotLoadedError{edge: "manifests"}
}

// VulnerabilitiesOrErr returns the Vulnerabilities value or an error if the edge
// was not loaded in eager-loading.
func (e ReportPackageEdges) VulnerabilitiesOrErr() ([]*ReportVulnerability, error) {
	if e.loadedTypes[1] {
		return e.Vulnerabilities, nil
	}
	return nil, &NotLoadedError{edge: "vulnerabilities"}
}

// LicensesOrErr returns the Licenses value or an error if the edge
// was not loaded in eager-loading.
func (e ReportPackageEdges) LicensesOrErr() ([]*ReportLicense, error) {
	if e.loadedTypes[2] {
		return e.Licenses, nil
	}
	return nil, &NotLoadedError{edge: "licenses"}
}

// DependenciesOrErr returns the Dependencies value or an error if the edge
// was not loaded in eager-loading.
func (e ReportPackageEdges) DependenciesOrErr() ([]*ReportDependency, error) {
	if e.loadedTypes[3] {
		return e.Dependencies, nil
	}
	return nil, &NotLoadedError{edge: "dependencies"}
}

// MalwareAnalysisOrErr returns the MalwareAnalysis value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ReportPackageEdges) MalwareAnalysisOrErr() (*ReportMalware, error) {
	if e.MalwareAnalysis != nil {
		return e.MalwareAnalysis, nil
	} else if e.loadedTypes[4] {
		return nil, &NotFoundError{label: reportmalware.Label}
	}
	return nil, &NotLoadedError{edge: "malware_analysis"}
}

// ProjectsOrErr returns the Projects value or an error if the edge
// was not loaded in eager-loading.
func (e ReportPackageEdges) ProjectsOrErr() ([]*ReportProject, error) {
	if e.loadedTypes[5] {
		return e.Projects, nil
	}
	return nil, &NotLoadedError{edge: "projects"}
}

// SlsaProvenancesOrErr returns the SlsaProvenances value or an error if the edge
// was not loaded in eager-loading.
func (e ReportPackageEdges) SlsaProvenancesOrErr() ([]*ReportSlsaProvenance, error) {
	if e.loadedTypes[6] {
		return e.SlsaProvenances, nil
	}
	return nil, &NotLoadedError{edge: "slsa_provenances"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*ReportPackage) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case reportpackage.FieldPackageDetails, reportpackage.FieldInsightsV2, reportpackage.FieldCodeAnalysis:
			values[i] = new([]byte)
		case reportpackage.FieldIsDirect, reportpackage.FieldIsMalware, reportpackage.FieldIsSuspicious:
			values[i] = new(sql.NullBool)
		case reportpackage.FieldID, reportpackage.FieldDepth:
			values[i] = new(sql.NullInt64)
		case reportpackage.FieldPackageID, reportpackage.FieldName, reportpackage.FieldVersion, reportpackage.FieldEcosystem, reportpackage.FieldPackageURL:
			values[i] = new(sql.NullString)
		case reportpackage.FieldCreatedAt, reportpackage.FieldUpdatedAt:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the ReportPackage fields.
func (rp *ReportPackage) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case reportpackage.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			rp.ID = int(value.Int64)
		case reportpackage.FieldPackageID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field package_id", values[i])
			} else if value.Valid {
				rp.PackageID = value.String
			}
		case reportpackage.FieldName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field name", values[i])
			} else if value.Valid {
				rp.Name = value.String
			}
		case reportpackage.FieldVersion:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field version", values[i])
			} else if value.Valid {
				rp.Version = value.String
			}
		case reportpackage.FieldEcosystem:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field ecosystem", values[i])
			} else if value.Valid {
				rp.Ecosystem = value.String
			}
		case reportpackage.FieldPackageURL:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field package_url", values[i])
			} else if value.Valid {
				rp.PackageURL = value.String
			}
		case reportpackage.FieldDepth:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field depth", values[i])
			} else if value.Valid {
				rp.Depth = int(value.Int64)
			}
		case reportpackage.FieldIsDirect:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field is_direct", values[i])
			} else if value.Valid {
				rp.IsDirect = value.Bool
			}
		case reportpackage.FieldIsMalware:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field is_malware", values[i])
			} else if value.Valid {
				rp.IsMalware = value.Bool
			}
		case reportpackage.FieldIsSuspicious:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field is_suspicious", values[i])
			} else if value.Valid {
				rp.IsSuspicious = value.Bool
			}
		case reportpackage.FieldPackageDetails:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field package_details", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &rp.PackageDetails); err != nil {
					return fmt.Errorf("unmarshal field package_details: %w", err)
				}
			}
		case reportpackage.FieldInsightsV2:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field insights_v2", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &rp.InsightsV2); err != nil {
					return fmt.Errorf("unmarshal field insights_v2: %w", err)
				}
			}
		case reportpackage.FieldCodeAnalysis:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field code_analysis", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &rp.CodeAnalysis); err != nil {
					return fmt.Errorf("unmarshal field code_analysis: %w", err)
				}
			}
		case reportpackage.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				rp.CreatedAt = value.Time
			}
		case reportpackage.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				rp.UpdatedAt = value.Time
			}
		default:
			rp.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the ReportPackage.
// This includes values selected through modifiers, order, etc.
func (rp *ReportPackage) Value(name string) (ent.Value, error) {
	return rp.selectValues.Get(name)
}

// QueryManifests queries the "manifests" edge of the ReportPackage entity.
func (rp *ReportPackage) QueryManifests() *ReportPackageManifestQuery {
	return NewReportPackageClient(rp.config).QueryManifests(rp)
}

// QueryVulnerabilities queries the "vulnerabilities" edge of the ReportPackage entity.
func (rp *ReportPackage) QueryVulnerabilities() *ReportVulnerabilityQuery {
	return NewReportPackageClient(rp.config).QueryVulnerabilities(rp)
}

// QueryLicenses queries the "licenses" edge of the ReportPackage entity.
func (rp *ReportPackage) QueryLicenses() *ReportLicenseQuery {
	return NewReportPackageClient(rp.config).QueryLicenses(rp)
}

// QueryDependencies queries the "dependencies" edge of the ReportPackage entity.
func (rp *ReportPackage) QueryDependencies() *ReportDependencyQuery {
	return NewReportPackageClient(rp.config).QueryDependencies(rp)
}

// QueryMalwareAnalysis queries the "malware_analysis" edge of the ReportPackage entity.
func (rp *ReportPackage) QueryMalwareAnalysis() *ReportMalwareQuery {
	return NewReportPackageClient(rp.config).QueryMalwareAnalysis(rp)
}

// QueryProjects queries the "projects" edge of the ReportPackage entity.
func (rp *ReportPackage) QueryProjects() *ReportProjectQuery {
	return NewReportPackageClient(rp.config).QueryProjects(rp)
}

// QuerySlsaProvenances queries the "slsa_provenances" edge of the ReportPackage entity.
func (rp *ReportPackage) QuerySlsaProvenances() *ReportSlsaProvenanceQuery {
	return NewReportPackageClient(rp.config).QuerySlsaProvenances(rp)
}

// Update returns a builder for updating this ReportPackage.
// Note that you need to call ReportPackage.Unwrap() before calling this method if this ReportPackage
// was returned from a transaction, and the transaction was committed or rolled back.
func (rp *ReportPackage) Update() *ReportPackageUpdateOne {
	return NewReportPackageClient(rp.config).UpdateOne(rp)
}

// Unwrap unwraps the ReportPackage entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (rp *ReportPackage) Unwrap() *ReportPackage {
	_tx, ok := rp.config.driver.(*txDriver)
	if !ok {
		panic("ent: ReportPackage is not a transactional entity")
	}
	rp.config.driver = _tx.drv
	return rp
}

// String implements the fmt.Stringer.
func (rp *ReportPackage) String() string {
	var builder strings.Builder
	builder.WriteString("ReportPackage(")
	builder.WriteString(fmt.Sprintf("id=%v, ", rp.ID))
	builder.WriteString("package_id=")
	builder.WriteString(rp.PackageID)
	builder.WriteString(", ")
	builder.WriteString("name=")
	builder.WriteString(rp.Name)
	builder.WriteString(", ")
	builder.WriteString("version=")
	builder.WriteString(rp.Version)
	builder.WriteString(", ")
	builder.WriteString("ecosystem=")
	builder.WriteString(rp.Ecosystem)
	builder.WriteString(", ")
	builder.WriteString("package_url=")
	builder.WriteString(rp.PackageURL)
	builder.WriteString(", ")
	builder.WriteString("depth=")
	builder.WriteString(fmt.Sprintf("%v", rp.Depth))
	builder.WriteString(", ")
	builder.WriteString("is_direct=")
	builder.WriteString(fmt.Sprintf("%v", rp.IsDirect))
	builder.WriteString(", ")
	builder.WriteString("is_malware=")
	builder.WriteString(fmt.Sprintf("%v", rp.IsMalware))
	builder.WriteString(", ")
	builder.WriteString("is_suspicious=")
	builder.WriteString(fmt.Sprintf("%v", rp.IsSuspicious))
	builder.WriteString(", ")
	builder.WriteString("package_details=")
	builder.WriteString(fmt.Sprintf("%v", rp.PackageDetails))
	builder.WriteString(", ")
	builder.WriteString("insights_v2=")
	builder.WriteString(fmt.Sprintf("%v", rp.InsightsV2))
	builder.WriteString(", ")
	builder.WriteString("code_analysis=")
	builder.WriteString(fmt.Sprintf("%v", rp.CodeAnalysis))
	builder.WriteString(", ")
	builder.WriteString("created_at=")
	builder.WriteString(rp.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("updated_at=")
	builder.WriteString(rp.UpdatedAt.Format(time.ANSIC))
	builder.WriteByte(')')
	return builder.String()
}

// ReportPackages is a parsable slice of ReportPackage.
type ReportPackages []*ReportPackage
