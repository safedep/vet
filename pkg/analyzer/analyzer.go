package analyzer

import (
	"github.com/safedep/vet/gen/filtersuite"
	jsonreportspec "github.com/safedep/vet/gen/jsonreport"
	"github.com/safedep/vet/pkg/models"
)

type AnalyzerEventType string

const (
	ET_FilterExpressionMatched = AnalyzerEventType("ev_pkg_filter_match")
	ET_AnalyzerFailOnError     = AnalyzerEventType("ev_fail_on_error")

	// Following event types must set the Threat field
	ET_LockfilePoisoningSignal = AnalyzerEventType("ev_lockfile_poisoning")
)

type AnalyzerEvent struct {
	// Analyzer generating this event
	Source string

	// Type of the event
	Type AnalyzerEventType

	// Message / Error / Filter
	Message interface{}
	Filter  *filtersuite.Filter
	Threat  *jsonreportspec.ReportThreat
	Err     error

	// Entities on which event was generated
	Manifest *models.PackageManifest
	Package  *models.Package
}

// Callback to receive events from analyzer
type AnalyzerEventHandler func(event *AnalyzerEvent) error

// Contract for an analyzer
type Analyzer interface {
	Name() string

	Analyze(manifest *models.PackageManifest,
		handler AnalyzerEventHandler) error

	Finish() error
}
