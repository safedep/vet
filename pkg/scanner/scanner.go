package scanner

import (
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/common/utils"
	"github.com/safedep/vet/pkg/models"
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
}

func NewPackageManifestScanner(config Config,
	enrichers []PackageMetaEnricher,
	analyzers []analyzer.Analyzer) *packageManifestScanner {
	return &packageManifestScanner{
		config:    config,
		enrichers: enrichers,
		analyzers: analyzers,
	}
}

// Autodiscover lockfiles
func (s *packageManifestScanner) ScanDirectory(dir string) error {
	logger.Infof("Starting package manifest scanner on dir: %s", dir)

	manifests, err := scanDirectoryForManifests(dir)
	if err != nil {
		logger.Errorf("Failed to scan directory: %v", err)
		return err
	}

	logger.Infof("Discovered %d manifest(s)", len(manifests))
	return s.analyzeManifests(manifests)
}

// Scan specific lockfiles, optionally interpreted as instead of
// automatic parser selection
func (s *packageManifestScanner) ScanLockfiles(lockfiles []string,
	lockfileAs string) error {
	logger.Infof("Scannding %d lockfiles as %s", len(lockfiles), lockfileAs)

	manifests, err := scanLockfilesForManifests(lockfiles, lockfileAs)
	if err != nil {
		logger.Errorf("Failed to scan lockfiles: %v", err)
		return err
	}

	logger.Infof("Discovered %d manifest(s)", len(manifests))
	return s.analyzeManifests(manifests)
}

func (s *packageManifestScanner) analyzeManifests(manifests []*models.PackageManifest) error {
	for _, manifest := range manifests {
		logger.Infof("Analysing %s as %s ecosystem with %d packages", manifest.Path,
			manifest.Ecosystem, len(manifest.Packages))

		err := s.enrichManifest(manifest)
		if err != nil {
			logger.Errorf("Failed to enrich %s manifest %s : %v",
				manifest.Ecosystem, manifest.Path, err)
		}

		err = s.analyzeManifest(manifest)
		if err != nil {
			logger.Errorf("Failed to analyze %s manifest %v : %v",
				manifest.Ecosystem, manifest.Path, err)
		}
	}

	return nil
}

func (s *packageManifestScanner) analyzeManifest(manifest *models.PackageManifest) error {
	for _, task := range s.analyzers {
		err := task.Analyze(manifest, func(event *analyzer.AnalyzerEvent) error {
			// Handle analyzer event
			return nil
		})
		if err != nil {
			logger.Errorf("Analyzer %s failed: %v", task.Name(), err)
		}
	}

	return nil
}

func (s *packageManifestScanner) enrichManifest(manifest *models.PackageManifest) error {
	// FIXME: Potential deadlock situation in case of channel buffer is full
	// because the goroutines perform both read and write to channel. Write occurs
	// when goroutine invokes the work queue handler and the handler pushes back
	// the dependencies
	q := utils.NewWorkQueue[*models.Package](100000,
		s.config.ConcurrentAnalyzer,
		s.packageEnrichWorkQueueHandler())
	q.Start()

	for _, pkg := range manifest.Packages {
		q.Add(pkg)
	}

	q.Wait()
	q.Stop()

	return nil
}

func (s *packageManifestScanner) packageEnrichWorkQueueHandler() utils.WorkQueueFn[*models.Package] {
	return func(q *utils.WorkQueue[*models.Package], item *models.Package) error {
		for _, enricher := range s.enrichers {
			err := enricher.Enrich(item, s.packageDependencyHandler(q))
			if err != nil {
				logger.Errorf("Enricher %s failed with %v", enricher.Name(), err)
			}
		}

		return nil
	}
}

func (s *packageManifestScanner) packageDependencyHandler(q *utils.WorkQueue[*models.Package]) PackageDependencyCallbackFn {
	return func(pkg *models.Package) error {
		if !s.config.TransitiveAnalysis {
			return nil
		}

		if pkg.Depth >= s.config.TransitiveDepth {
			return nil
		}

		logger.Debugf("Adding transitive dependency %s/%v to work queue",
			pkg.PackageDetails.Name, pkg.PackageDetails.Version)
		q.Add(pkg)

		return nil
	}
}
