package scanner

import (
	"context"
	"fmt"
	"sync"

	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/common/utils"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
	"github.com/safedep/vet/pkg/reporter"
)

type Config struct {
	ExcludePatterns    []string
	ConcurrentAnalyzer int
	TransitiveAnalysis bool
	TransitiveDepth    int
}

type packageManifestScanner struct {
	config    Config
	readers   []readers.PackageManifestReader
	enrichers []PackageMetaEnricher
	analyzers []analyzer.Analyzer
	reporters []reporter.Reporter

	callbacks   ScannerCallbacks
	failOnError error
}

func NewPackageManifestScanner(config Config,
	readers []readers.PackageManifestReader,
	enrichers []PackageMetaEnricher,
	analyzers []analyzer.Analyzer,
	reporters []reporter.Reporter) *packageManifestScanner {
	return &packageManifestScanner{
		config:    config,
		readers:   readers,
		enrichers: enrichers,
		analyzers: analyzers,
		reporters: reporters,
	}
}

func (s *packageManifestScanner) Start() error {
	s.dispatchOnStart()

	scannerChannel := make(chan *models.PackageManifest, 100)
	defer close(scannerChannel)

	ctx := context.Background()
	defer ctx.Done()

	wg := sync.WaitGroup{}
	go s.startManifestScanner(ctx, scannerChannel, &wg)

	s.dispatchStartManifestEnumeration()

	for _, reader := range s.readers {
		err := reader.EnumManifests(func(manifest *models.PackageManifest,
			_ readers.PackageReader) error {

			wg.Add(1)

			s.dispatchOnManifestEnumeration(manifest)
			scannerChannel <- manifest

			return nil
		})

		if err != nil {
			return err
		}
	}

	// Wait for manifest scanner to finish
	wg.Wait()

	s.dispatchBeforeFinish()

	// Signal analyzers and reporters to finish anything pending
	s.finishAnalyzers()
	s.finishReporting()

	s.dispatchOnStop(s.error())
	return s.error()
}

// startManifestScanner internally takes input from channel and scans the manifest
// The object is NOT to scan manifests in parallel but to build a work queue like
// mechanism where we can scan a manifest whenever it is available instead of waiting
// for all manifests to be available
func (s *packageManifestScanner) startManifestScanner(ctx context.Context,
	incoming <-chan *models.PackageManifest, waiter *sync.WaitGroup) {

	// Start the scan phases per manifest
	for {
		if err := ctx.Err(); err != nil {
			break
		}

		// Stop scan if there is a pending error
		if s.hasError() {
			break
		}

		manifest := <-incoming
		s.dispatchOnStartManifest(manifest)

		// We are using a function here so that we can use `defer` to ensure
		// we always mark the wait group irrespective of success or failure
		func() {
			defer waiter.Done()

			// Enrich each packages in a manifest with metadata
			err := s.enrichManifest(manifest)
			if err != nil {
				logger.Errorf("Failed to enrich %s manifest %s : %v",
					manifest.Ecosystem, manifest.GetPath(), err)
			}

			// Invoke analyzers to analyse the manifest
			err = s.analyzeManifest(manifest)
			if err != nil {
				logger.Errorf("Failed to analyze %s manifest %s : %v",
					manifest.Ecosystem, manifest.GetPath(), err)
			}

			// Invoke activated reporting modules to report on the manifest
			err = s.reportManifest(manifest)
			if err != nil {
				logger.Errorf("Failed to report %s manifest %s : %v",
					manifest.Ecosystem, manifest.GetPath(), err)
			}

			s.dispatchOnDoneManifest(manifest)
		}()
	}
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

	q.WithCallbacks(utils.WorkQueueCallbacks[*models.Package]{
		OnAdd: func(q *utils.WorkQueue[*models.Package], item *models.Package) {
			s.dispatchOnStartPackage(item)
		},
		OnDone: func(q *utils.WorkQueue[*models.Package], item *models.Package) {
			s.dispatchOnDonePackage(item)
		},
	})

	q.Start()

	readers.NewManifestModelReader(manifest).EnumPackages(func(pkg *models.Package) error {
		q.Add(pkg)
		return nil
	})

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

		logger.Debugf("Adding transitive dependency %s/%s to work queue",
			pkg.PackageDetails.Name, pkg.PackageDetails.Version)

		if q.Add(pkg) {
			pm.AddPackage(pkg)
			s.dispatchOnAddTransitivePackage(pkg)
		}

		return nil
	}
}
