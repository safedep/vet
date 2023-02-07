package scanner

import "github.com/safedep/vet/pkg/models"

type ScannerCallbackOnManifestsFn func(manifest []*models.PackageManifest)

type ScannerCallbackOnManifestFn func(manifest *models.PackageManifest)

type ScannerCallbackOnPackageFn func(pkg *models.Package)

type ScannerCallbackErrArgFn func(error)

type ScannerCallbackNoArgFn func()

type ScannerCallbacks struct {
	OnStart         ScannerCallbackOnManifestsFn
	OnStartManifest ScannerCallbackOnManifestFn
	OnStartPackage  ScannerCallbackOnPackageFn
	OnDonePackage   ScannerCallbackOnPackageFn
	OnDoneManifest  ScannerCallbackOnManifestFn
	BeforeFinish    ScannerCallbackNoArgFn
	OnStop          ScannerCallbackErrArgFn
}

func (s *packageManifestScanner) WithCallbacks(callbacks ScannerCallbacks) {
	s.callbacks = callbacks
}

func (s *packageManifestScanner) dispatchOnStart(manifests []*models.PackageManifest) {
	if s.callbacks.OnStart != nil {
		s.callbacks.OnStart(manifests)
	}
}

func (s *packageManifestScanner) dispatchOnStartManifest(manifest *models.PackageManifest) {
	if s.callbacks.OnStartManifest != nil {
		s.callbacks.OnStartManifest(manifest)
	}
}

func (s *packageManifestScanner) dispatchOnStartPackage(pkg *models.Package) {
	if s.callbacks.OnStartPackage != nil {
		s.callbacks.OnStartPackage(pkg)
	}
}

func (s *packageManifestScanner) dispatchOnDonePackage(pkg *models.Package) {
	if s.callbacks.OnDonePackage != nil {
		s.callbacks.OnDonePackage(pkg)
	}
}

func (s *packageManifestScanner) dispatchOnDoneManifest(manifest *models.PackageManifest) {
	if s.callbacks.OnDoneManifest != nil {
		s.callbacks.OnDoneManifest(manifest)
	}
}

func (s *packageManifestScanner) dispatchBeforeFinish() {
	if s.callbacks.BeforeFinish != nil {
		s.callbacks.BeforeFinish()
	}
}

func (s *packageManifestScanner) dispatchOnStop(err error) {
	if s.callbacks.OnStop != nil {
		s.callbacks.OnStop(err)
	}
}
