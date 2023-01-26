package reporter

import (
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
)

type Reporter interface {
	Name() string

	// Feed collected data to reporting module
	AddManifest(manifest *models.PackageManifest)
	AddAnalyzerEvent(event *analyzer.AnalyzerEvent)
	AddPolicyEvent(event *policy.PolicyEvent)

	// Inform reporting module to finalise (e.g. write report to file)
	Finish() error
}
