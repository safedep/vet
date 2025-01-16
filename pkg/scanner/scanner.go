package scanner

import (
	"context"
	"fmt"

	dryutils "github.com/safedep/dry/utils"
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
	Experimental       bool
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

	// The manifest processing go routine will close the doneChannel
	doneChannel := make(chan bool)

	// We will close the scanner channel
	scannerChannel := make(chan *models.PackageManifest, 100)

	ctx := context.Background()
	defer ctx.Done()

	go s.startManifestScanner(ctx, scannerChannel, doneChannel)

	s.dispatchStartManifestEnumeration()

	for _, reader := range s.readers {
		err := reader.EnumManifests(func(manifest *models.PackageManifest,
			_ readers.PackageReader) error {

			s.dispatchOnManifestEnumeration(manifest)
			scannerChannel <- manifest

			return nil
		})

		if err != nil {
			return err
		}
	}

	// Close this channel so that go routine processing the manifests
	// can break the loop
	close(scannerChannel)

	// Wait for manifest scanner to finish
	<-doneChannel

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
	incoming <-chan *models.PackageManifest, done chan bool) {
	defer close(done)

	// Start the scan phases per manifest
	for {
		if err := ctx.Err(); err != nil {
			break
		}

		// Stop scan if there is a pending error
		if s.hasError() {
			break
		}

		manifest, ok := <-incoming
		if !ok {
			break
		}

		s.dispatchOnStartManifest(manifest)

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

	defer s.finaliseDependencyGraph(manifest)

	// FIXME: Potential deadlock situation in case of channel buffer is full
	// because the goroutines perform both read and write to channel. Write occurs
	// when goroutine invokes the work queue handler and the handler pushes back
	// the dependencies
	q := utils.NewWorkQueue(100000,
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

	// Finally wait for all enrichers to finish
	err := s.packageEnricherWait()
	if err != nil {
		return fmt.Errorf("package enricher wait failed: %w", err)
	}

	return nil
}

func (s *packageManifestScanner) packageEnricherWait() error {
	for _, enricher := range s.enrichers {
		logger.Debugf("Waiting for enricher %s to finish", enricher.Name())

		err := enricher.Wait()
		if err != nil {
			logger.Errorf("Failed to wait for enricher %s: %v", enricher.Name(), err)
		}
	}

	return nil
}

func (s *packageManifestScanner) packageEnrichWorkQueueHandler(pm *models.PackageManifest) utils.WorkQueueFn[*models.Package] {
	return func(q *utils.WorkQueue[*models.Package], item *models.Package) error {
		for _, enricher := range s.enrichers {
			err := enricher.Enrich(item, s.packageDependencyHandler(pm, item, q))
			if err != nil {
				logger.Errorf("Enricher %s failed with %v", enricher.Name(), err)
			}
		}

		return nil
	}
}

func (s *packageManifestScanner) packageDependencyHandler(pm *models.PackageManifest,
	_ *models.Package,
	q *utils.WorkQueue[*models.Package]) PackageDependencyCallbackFn {
	return func(pkg *models.Package) error {
		// Check and queue for further analysis
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

// finaliseDependencyGraph attempts to mark some nodes as root node if they do not have a dependent
// this is just a heuristic to mark some nodes as root node. This may not be accurate in all cases
func (s *packageManifestScanner) finaliseDependencyGraph(manifest *models.PackageManifest) {
	if manifest.DependencyGraph == nil {
		return
	}

	if manifest.DependencyGraph.Present() {
		return
	}

	// Building dependency graph using package insights
	packages := manifest.GetPackages()
	for _, pkg := range packages {
		insights := dryutils.SafelyGetValue(pkg.Insights)
		dependencies := dryutils.SafelyGetValue(insights.Dependencies)

		for _, dep := range dependencies {
			distance := dryutils.SafelyGetValue(dep.Distance)

			// Distance = 0 is the package itself
			if distance == 0 {
				continue
			}

			// Distance > 1 means the package is not a direct dependency
			if distance > 1 {
				continue
			}

			logger.Debugf("Adding dependency %s/%s to dependency graph",
				dep.PackageVersion.Name, dep.PackageVersion.Version)

			targetPkg := utils.FindDependencyGraphNodeBySemverRange(manifest.DependencyGraph,
				dep.PackageVersion.Name, dep.PackageVersion.Version)

			if targetPkg == nil {
				logger.Debugf("Dependency %s/%s not found in dependency graph",
					dep.PackageVersion.Name, dep.PackageVersion.Version)
				continue
			}

			manifest.DependencyGraph.AddDependency(pkg, targetPkg.Data)
		}
	}

	nodes := manifest.DependencyGraph.GetNodes()
	for _, node := range nodes {
		pkg := node.Data
		dependents := manifest.DependencyGraph.GetDependents(pkg)
		if len(dependents) == 0 {
			node.SetRoot(true)
		}
	}

	manifest.DependencyGraph.SetPresent(true)
}
