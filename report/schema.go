package report

import (
	"encoding/json"
	"reflect"

	"github.com/invopop/jsonschema"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

// Document is the shape of "-o json": the header, the records and the
// trailer. vet writes it record by record and never holds it in memory.
type Document struct {
	Header  Header   `json:"header"`
	Records []Record `json:"records"`
	Trailer Trailer  `json:"trailer"`
}

// Schema returns the JSON Schema of Document, generated from the Go types.
func Schema() ([]byte, error) {
	return schemaOf(&Document{}, enumSchema, SchemaURL, "vet report",
		"The local report of a vet scan, schema version "+SchemaVersion+".")
}

// LineSchema returns the JSON Schema of one line of "-o jsonl": the
// header, one record or the trailer.
func LineSchema() ([]byte, error) {
	lineKinds := func(t reflect.Type) *jsonschema.Schema {
		if t == reflect.TypeFor[Kind]() {
			return stringEnum(append(recordKinds(), string(LineHeader), string(LineTrailer))...)
		}
		return enumSchema(t)
	}
	return schemaOf(&Line{}, lineKinds, LineSchemaURL, "vet report line",
		"One line of the jsonl report of a vet scan, schema version "+SchemaVersion+".")
}

func schemaOf(v any, mapper func(reflect.Type) *jsonschema.Schema, id, title, desc string) ([]byte, error) {
	r := &jsonschema.Reflector{
		// A minor schema version can add fields. A reader must keep working.
		AllowAdditionalProperties: true,
		Mapper:                    mapper,
		Namer:                     schemaName,
	}
	s := r.Reflect(v)
	s.ID = jsonschema.ID(id)
	s.Title = title
	s.Description = desc
	return json.MarshalIndent(s, "", "  ")
}

// schemaName names the JSON shape of model.PackageVersion after the type.
func schemaName(t reflect.Type) string {
	if t == reflect.TypeOf(model.PackageVersion{}.JSONSchemaAlias()) {
		return "PackageVersion"
	}
	return t.Name()
}

func recordKinds() []string {
	return []string{string(KindManifest), string(KindPackage), string(KindInventory), string(KindFinding), string(KindDiagnostic), string(KindCapability)}
}

// enumSchema maps each closed enum to a string schema with its values.
func enumSchema(t reflect.Type) *jsonschema.Schema {
	var values []string
	switch t {
	case reflect.TypeFor[finding.Severity]():
		for _, v := range finding.Severities() {
			values = append(values, string(v))
		}
	case reflect.TypeFor[finding.Family]():
		for _, v := range finding.Families() {
			values = append(values, string(v))
		}
	case reflect.TypeFor[finding.Confidence]():
		values = []string{string(finding.ConfidenceHigh), string(finding.ConfidenceMedium), string(finding.ConfidenceLow)}
	case reflect.TypeFor[finding.SubjectKind]():
		values = []string{string(finding.SubjectPackage), string(finding.SubjectFile), string(finding.SubjectManifest), string(finding.SubjectApplication)}
	case reflect.TypeFor[model.Change]():
		values = []string{
			string(model.ChangeNone), string(model.ChangeAdded), string(model.ChangeUpgraded), string(model.ChangeDowngraded),
			string(model.ChangeModified), string(model.ChangeRemoved), string(model.ChangeUnchanged),
		}
	case reflect.TypeFor[model.Ecosystem]():
		for _, v := range model.Ecosystems() {
			values = append(values, string(v))
		}
	case reflect.TypeFor[model.ManifestKind]():
		values = []string{
			string(model.ManifestKindLockfile), string(model.ManifestKindManifest), string(model.ManifestKindWorkflow),
			string(model.ManifestKindSBOM), string(model.ManifestKindImage), string(model.ManifestKindPURL), string(model.ManifestKindEndpoint),
			string(model.ManifestKindAgentConfig),
		}
	case reflect.TypeFor[Kind]():
		values = recordKinds()
	case reflect.TypeFor[ScanKind]():
		values = []string{string(ScanKindScan), string(ScanKindEndpoint)}
	case reflect.TypeFor[ScanMode]():
		values = []string{string(ScanModeFull), string(ScanModeDelta)}
	case reflect.TypeFor[InventoryKind]():
		values = []string{string(InventoryAITool), string(InventoryMCPServer), string(InventorySkill), string(InventoryEditorPlugin)}
	case reflect.TypeFor[DiagnosticLevel]():
		values = []string{string(DiagnosticWarning), string(DiagnosticError)}
	case reflect.TypeFor[GateOutcome]():
		values = []string{string(GateNone), string(GatePass), string(GateFail)}
	default:
		return nil
	}

	return stringEnum(values...)
}

func stringEnum(values ...string) *jsonschema.Schema {
	enum := make([]any, len(values))
	for i, v := range values {
		enum[i] = v
	}
	return &jsonschema.Schema{Type: "string", Enum: enum}
}
