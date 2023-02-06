package scanner

import (
	"fmt"

	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/common/utils"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/reporter"
)

type Config struct {
	ConcurrentAnalyzer int
	TransitiveAnalysis bool
	TransitiveDepth    int
}

type packageManifestScanner struct {
	config    Config
	enrichers []PackageMetaEnricher
	analyzers []analyzer.Analyzer
	reporters []reporter.Reporter

	failOnError error
}

func NewPackageManifestScanner(config Config,
	enrichers []PackageMetaEnricher,
	analyzers []analyzer.Analyzer,
	reporters []reporter.Reporter) *packageManifestScanner {
	return &packageManifestScanner{
		config:    config,
		enrichers: enrichers,
		analyzers: analyzers,
		reporters: reporters,
	}
}

// Autodiscover lockfiles
func (s *packageManifestScanner) ScanDirectory(dir string) error {
	logger.Infof("Starting package manifest scanner on dir: %s", dir)

	manifests, err := scanDirectoryForManifests(dir)
	if err != nil {
		return err
	}

	logger.Infof("Discovered %d manifest(s)", len(manifests))
	return s.scanManifests(manifests)
}

// Scan specific lockfiles, optionally interpreted as instead of
// automatic parser selection
func (s *packageManifestScanner) ScanLockfiles(lockfiles []string,
	lockfileAs string) error {
	logger.Infof("Scannding %d lockfiles as %s", len(lockfiles), lockfileAs)

	manifests, err := scanLockfilesForManifests(lockfiles, lockfileAs)
	if err != nil {
		return err
	}

	logger.Infof("Discovered %d manifest(s)", len(manifests))
	return s.scanManifests(manifests)
}

// Load the manifests from a previous dumped JSON file
func (s *packageManifestScanner) ScanDumpDirectory(dir string) error {
	logger.Infof("Scan dump files to load as manifests: %s", dir)

	manifests, err := scanDumpFilesForManifest(dir)
	if err != nil {
		return err
	}

	logger.Infof("Loaded %d manifest(s)", len(manifests))
	return s.scanManifests(manifests)
}

func (s *packageManifestScanner) scanManifests(manifests []*models.PackageManifest) error {
	// Start the scan phases per manifest
	for _, manifest := range manifests {
		logger.Infof("Analysing %s as %s ecosystem with %d packages", manifest.Path,
			manifest.Ecosystem, len(manifest.Packages))

		// Stop scan if there is a pendin error
		if s.hasError() {
			break
		}

		// Enrich each packages in a manifest with metadata
		err := s.enrichManifest(manifest)
		if err != nil {
			logger.Errorf("Failed to enrich %s manifest %s : %v",
				manifest.Ecosystem, manifest.Path, err)
		}

		// Invoke analyzers to analyse the manifest
		err = s.analyzeManifest(manifest)
		if err != nil {
			logger.Errorf("Failed to analyze %s manifest %s : %v",
				manifest.Ecosystem, manifest.Path, err)
		}

		// Invoke activated reporting modules to report on the manifest
		err = s.reportManifest(manifest)
		if err != nil {
			logger.Errorf("Failed to report %s manifest %s : %v",
				manifest.Ecosystem, manifest.Path, err)
		}
	}

	// Signal analyzers and reporters to finish anything pending
	s.finishAnalyzers()
	s.finishReporting()

	return s.error()
}

func (s *packageManifestScanner) analyzeManifest(manifest *models.PackageManifest) error {
	for _, task := range s.analyzers {
		err := task.Analyze(manifest, func(event *analyzer.AnalyzerEvent) error {
			for _, r := range s.reporters {
				r.AddAnalyzerEvent(event)
			}

			return s.internalHandleAnalyzerEvent(event)
		})

		if err != nil {
			logger.Errorf("Analyzer %s failed: %v", task.Name(), err)
		}
	}

	return nil
}

func (s *packageManifestScanner) internalHandleAnalyzerEvent(event *analyzer.AnalyzerEvent) error {
	if event.IsFailOnError() {
		s.failWith(fmt.Errorf("%s analyzer raised an event to fail with: %w",
			event.Source, event.Err))
	}

	return nil
}

func (s *packageManifestScanner) failWith(err error) {
	s.failOnError = err
}

func (s *packageManifestScanner) hasError() bool {
	return (s.error() != nil)
}

func (s *packageManifestScanner) error() error {
	return s.failOnError
}

func (s *packageManifestScanner) reportManifest(manifest *models.PackageManifest) error {
	for _, r := range s.reporters {
		r.AddManifest(manifest)
	}

	return nil
}

func (s *packageManifestScanner) finishReporting() {
	for _, r := range s.reporters {
		err := r.Finish()
		if err != nil {
			logger.Errorf("Reporter: %s failed with %v", r.Name(), err)
		}
	}
}

func (s *packageManifestScanner) finishAnalyzers() {
	for _, r := range s.analyzers {
		err := r.Finish()
		if err != nil {
			logger.Errorf("Analyzer: %s failed with %v", r.Name(), err)
		}
	}
}

func (s *packageManifestScanner) enrichManifest(manifest *models.PackageManifest) error {
	if len(s.enrichers) == 0 {
		return nil
	}

	// FIXME: Potential deadlock situation in case of channel buffer is full
	// because the goroutines perform both read and write to channel. Write occurs
	// when goroutine invokes the work queue handler and the handler pushes back
	// the dependencies
	q := utils.NewWorkQueue[*models.Package](100000,
		s.config.ConcurrentAnalyzer,
		s.packageEnrichWorkQueueHandler(manifest))
	q.Start()

	for _, pkg := range manifest.Packages {
		q.Add(pkg)
	}

	q.Wait()
	q.Stop()

	return nil
}

func (s *packageManifestScanner) packageEnrichWorkQueueHandler(pm *models.PackageManifest) utils.WorkQueueFn[*models.Package] {
	return func(q *utils.WorkQueue[*models.Package], item *models.Package) error {
		for _, enricher := range s.enrichers {
			err := enricher.Enrich(item, s.packageDependencyHandler(pm, q))
			if err != nil {
				logger.Errorf("Enricher %s failed with %v", enricher.Name(), err)
			}
		}

		return nil
	}
}

func (s *packageManifestScanner) packageDependencyHandler(pm *models.PackageManifest,
	q *utils.WorkQueue[*models.Package]) PackageDependencyCallbackFn {
	return func(pkg *models.Package) error {
		if !s.config.TransitiveAnalysis {
			return nil
		}

		if pkg.Depth >= s.config.TransitiveDepth {
			return nil
		}

		logger.Debugf("Adding transitive dependency %s/%v to work queue",
			pkg.PackageDetails.Name, pkg.PackageDetails.Version)

		if q.Add(pkg) {
			pm.AddPackage(pkg)
		}

		return nil
	}
}
