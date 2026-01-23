package scanner

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
	"github.com/safedep/vet/pkg/reporter"
)

// AgentSkillScannerConfig configures the skill scanner
type AgentSkillScannerConfig struct {
	// Whether to fail fast on malware detection
	FailFast bool
}

// DefaultAgentSkillScannerConfig returns the default configuration
func DefaultAgentSkillScannerConfig() AgentSkillScannerConfig {
	return AgentSkillScannerConfig{
		FailFast: true,
	}
}

// agentSkillScanner is a purpose-built scanner for Agent Skills
// It's simpler and more opinionated than the general packageManifestScanner
type agentSkillScanner struct {
	config    AgentSkillScannerConfig
	reader    readers.PackageManifestReader
	enricher  PackageMetaEnricher
	analyzer  analyzer.Analyzer
	reporters []reporter.Reporter

	// Error state
	failOnError error
}

// NewAgentSkillScanner creates a new scanner for Agent Skills
func NewAgentSkillScanner(
	config AgentSkillScannerConfig,
	reader readers.PackageManifestReader,
	enricher PackageMetaEnricher,
	analyzer analyzer.Analyzer,
	reporters []reporter.Reporter,
) *agentSkillScanner {
	return &agentSkillScanner{
		config:    config,
		reader:    reader,
		enricher:  enricher,
		analyzer:  analyzer,
		reporters: reporters,
	}
}

// Start begins the skill scanning process
func (s *agentSkillScanner) Start() error {
	logger.Infof("Starting Agent Skill scan")

	var manifest *models.PackageManifest
	err := s.reader.EnumManifests(func(pm *models.PackageManifest, _ readers.PackageReader) error {
		manifest = pm
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to read skill manifest: %w", err)
	}

	if manifest == nil {
		return fmt.Errorf("no skill manifest found")
	}

	logger.Infof("Scanning skill from: %s", manifest.GetDisplayPath())

	// Enrich the skill package with malware analysis
	err = s.enrichSkill(manifest)
	if err != nil {
		return fmt.Errorf("failed to enrich skill: %w", err)
	}

	// Analyze the skill for malware
	err = s.analyzeSkill(manifest)
	if err != nil {
		return fmt.Errorf("failed to analyze skill: %w", err)
	}

	// Generate reports
	err = s.reportSkill(manifest)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Finish reporting
	s.finishReporting()

	return s.error()
}

// enrichSkill enriches the skill package with malware analysis data
func (s *agentSkillScanner) enrichSkill(manifest *models.PackageManifest) error {
	if s.enricher == nil {
		return fmt.Errorf("no enricher configured")
	}

	logger.Infof("Enriching skill with malware analysis")

	// Get the single package from the manifest (skills have only one package)
	packages := manifest.GetPackages()
	if len(packages) == 0 {
		return fmt.Errorf("no packages found in manifest")
	}

	pkg := packages[0]

	// Enrich the package
	err := s.enricher.Enrich(pkg, func(dep *models.Package) error {
		// Skills don't have dependencies to enrich
		return nil
	})
	if err != nil {
		// Check if its gRPC not found. This is expected for some packages
		// especially in query mode.
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return nil
		}

		return fmt.Errorf("failed to enrich package: %w", err)
	}

	// Wait for enrichment to complete
	logger.Debugf("Waiting for enrichment to complete")
	err = s.enricher.Wait()
	if err != nil {
		return fmt.Errorf("enricher wait failed: %w", err)
	}

	logger.Infof("Enrichment completed successfully")
	return nil
}

// analyzeSkill analyzes the enriched skill for malware
func (s *agentSkillScanner) analyzeSkill(manifest *models.PackageManifest) error {
	if s.analyzer == nil {
		// No analyzer configured, skip analysis
		return nil
	}

	logger.Infof("Analyzing skill for malware")

	err := s.analyzer.Analyze(manifest, func(event *analyzer.AnalyzerEvent) error {
		// Forward events to reporters
		for _, r := range s.reporters {
			r.AddAnalyzerEvent(event)
		}

		// Handle fail-on-error events
		if event.IsFailOnError() {
			s.failWith(fmt.Errorf("%s analyzer raised an event to fail with: %w",
				event.Source, event.Err))
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("analyzer failed: %w", err)
	}

	// Finish analyzer
	err = s.analyzer.Finish()
	if err != nil {
		return fmt.Errorf("analyzer finish failed: %w", err)
	}

	logger.Infof("Analysis completed successfully")
	return nil
}

// reportSkill sends the manifest to all reporters
func (s *agentSkillScanner) reportSkill(manifest *models.PackageManifest) error {
	logger.Debugf("Generating reports")

	for _, r := range s.reporters {
		r.AddManifest(manifest)
	}

	return nil
}

// finishReporting finalizes all reporters
func (s *agentSkillScanner) finishReporting() {
	for _, r := range s.reporters {
		err := r.Finish()
		if err != nil {
			logger.Errorf("Reporter %s failed: %v", r.Name(), err)
		}
	}
}

// failWith sets an error that will cause the scan to fail
func (s *agentSkillScanner) failWith(err error) {
	s.failOnError = err
}

// error returns the current error state
func (s *agentSkillScanner) error() error {
	return s.failOnError
}
