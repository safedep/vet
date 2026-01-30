package bitbucket

// BitBucket Code Insights Data Structures
// Docs: https://support.atlassian.com/bitbucket-cloud/docs/code-insights/

type ReportType string

const (
	ReportTypeSecurity ReportType = "SECURITY"
	ReportTypeCoverage ReportType = "COVERAGE"
	ReportTypeTest     ReportType = "TEST"
)

type ReportResult string

const (
	ReportResultPassed ReportResult = "PASSED"
	ReportResultFailed ReportResult = "FAILED"
)

type DataType string

const (
	DataTypeBoolean    DataType = "BOOLEAN"
	DataTypeDate       DataType = "DATE"
	DataTypeDuration   DataType = "DURATION"
	DataTypeLink       DataType = "LINK"
	DataTypeNumber     DataType = "NUMBER"
	DataTypePercentage DataType = "PERCENTAGE"
	DataTypeString     DataType = "STRING"
	DataTypeText       DataType = "TEXT"
)

type AnnotationType string

const (
	AnnotationTypeVulnerability AnnotationType = "VULNERABILITY"
	AnnotationTypeCodeSmell     AnnotationType = "CODE_SMELL"
)

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
	Data       []*CodeInsightsData `json:"data,omitempty"` // Max 10 elements
}

type CodeInsightsData struct {
	Title string   `json:"title"`
	Type  DataType `json:"type"`
	Value any      `json:"value"`
}

type CodeInsightsAnnotation struct {
	ExternalID     string             `json:"external_id,omitempty"` // Unique ID from your system
	Title          string             `json:"title,omitempty"`
	AnnotationType AnnotationType     `json:"annotation_type"`
	Summary        string             `json:"summary"`
	Severity       AnnotationSeverity `json:"severity,omitempty"`
	FilePath       string             `json:"path,omitempty"`
	LineNumber     int                `json:"line,omitempty"`
	Link           string             `json:"link,omitempty"`
}
