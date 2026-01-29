package bitbucket

// BitBucket Code Insights Data Structures
// Docs: https://support.atlassian.com/bitbucket-cloud/docs/code-insights/

type ReportType string

const (
	ReportTypeSecurity ReportType = "SECURITY"
	ReportTypeCoverage ReportType = "COVERAGE"
	ReportTypeTest     ReportType = "TEST"
	ReportTypeBug      ReportType = "BUG"
)

// ReportResult represents the pass/fail status of the report.
type ReportResult string

const (
	ReportResultPassed  ReportResult = "PASSED"
	ReportResultFailed  ReportResult = "FAILED"
	ReportResultPending ReportResult = "PENDING"
)

// DataType represents the type of value in the report data fields.
type DataType string

const (
	DataTypeBoolean    DataType = "BOOLEAN"
	DataTypeDate       DataType = "DATE"
	DataTypeDuration   DataType = "DURATION"
	DataTypeLink       DataType = "LINK"
	DataTypeNumber     DataType = "NUMBER"
	DataTypePercentage DataType = "PERCENTAGE"
	DataTypeText       DataType = "TEXT"
)

// AnnotationType represents the category of the annotation.
type AnnotationType string

const (
	AnnotationTypeVulnerability AnnotationType = "VULNERABILITY"
	AnnotationTypeCodeSmell     AnnotationType = "CODE_SMELL"
	AnnotationTypeBug           AnnotationType = "BUG"
)

// AnnotationSeverity represents the severity level of the annotation.
type AnnotationSeverity string

const (
	AnnotationSeverityLow      AnnotationSeverity = "LOW"
	AnnotationSeverityMedium   AnnotationSeverity = "MEDIUM"
	AnnotationSeverityHigh     AnnotationSeverity = "HIGH"
	AnnotationSeverityCritical AnnotationSeverity = "CRITICAL"
)

type CodeInsightsReport struct {
	Title      string              `json:"title"`
	Details    string              `json:"details,omitempty"`
	ReportType ReportType          `json:"report_type"`
	Reporter   string              `json:"reporter,omitempty"`
	Link       string              `json:"link,omitempty"`
	Result     ReportResult        `json:"result,omitempty"`
	Data       []*CodeInsightsData `json:"data,omitempty"`
}

type CodeInsightsData struct {
	Title string   `json:"title"`
	Type  DataType `json:"type"`
	Value any      `json:"value"`
}

type CodeInsightsAnnotation struct {
	Title          string             `json:"title"`
	AnnotationType AnnotationType     `json:"annotation_type"`
	Summary        string             `json:"summary"`
	Severity       AnnotationSeverity `json:"severity"`
	FilePath       string             `json:"path,omitempty"`
	LineNumber     uint32             `json:"line,omitempty"`
	Link           string             `json:"link,omitempty"`
	ExternalID     string             `json:"external_id,omitempty"`
}
