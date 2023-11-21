package scanner

import "github.com/safedep/vet/pkg/models"

type ScannerCallbackOnManifestFn func(manifest *models.PackageManifest)

type ScannerCallbackOnPackageFn func(pkg *models.Package)

type ScannerCallbackErrArgFn func(error)

type ScannerCallbackNoArgFn func()

type ScannerCallbacks struct {
	OnStartEnumerateManifest ScannerCallbackNoArgFn      // Manifest enumeration is starting
	OnEnumerateManifest      ScannerCallbackOnManifestFn // A manifest is read by reader
	OnStart                  ScannerCallbackNoArgFn      // Manifest scan phase is starting
	OnStartManifest          ScannerCallbackOnManifestFn // A manifest is starting to be scanned
	OnStartPackage           ScannerCallbackOnPackageFn  // A package analysis is starting
	OnAddTransitivePackage   ScannerCallbackOnPackageFn  // A transitive dependency is discovered
	OnDonePackage            ScannerCallbackOnPackageFn  // A package analysis is finished
	OnDoneManifest           ScannerCallbackOnManifestFn // A manifest analysis is finished
	BeforeFinish             ScannerCallbackNoArgFn      // Scan is about to finish
	OnStop                   ScannerCallbackErrArgFn     // Scan is finished
}

func (s *packageManifestScanner) WithCallbacks(callbacks ScannerCallbacks) {
	s.callbacks = callbacks
}

func (s *packageManifestScanner) dispatchStartManifestEnumeration() {
	if s.callbacks.OnStartEnumerateManifest != nil {
		s.callbacks.OnStartEnumerateManifest()
	}
}

func (s *packageManifestScanner) dispatchOnManifestEnumeration(manifest *models.PackageManifest) {
	if s.callbacks.OnEnumerateManifest != nil {
		s.callbacks.OnEnumerateManifest(manifest)
	}
}

func (s *packageManifestScanner) dispatchOnStart() {
	if s.callbacks.OnStart != nil {
		s.callbacks.OnStart()
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

func (s *packageManifestScanner) dispatchOnAddTransitivePackage(pkg *models.Package) {
	if s.callbacks.OnAddTransitivePackage != nil {
		s.callbacks.OnAddTransitivePackage(pkg)
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
