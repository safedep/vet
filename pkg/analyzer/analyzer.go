package analyzer

import "github.com/safedep/vet/pkg/models"

type AnalyzerEventType string

const (
	ET_FilterExpressionMatched = AnalyzerEventType("ev_pkg_filter_match")
)

type AnalyzerEvent struct {
	// Analyzer generating this event
	Source string

	// Type of the event
	Type AnalyzerEventType

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
}
