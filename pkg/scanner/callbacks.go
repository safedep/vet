package scanner

import "github.com/safedep/vet/pkg/models"

type ScannerCallbackOnManifestFn func(manifest *models.PackageManifest)

type ScannerCallbackOnPackageFn func(pkg *models.Package)

type ScannerCallbackNoArgFn func()

type ScannerCallbacks struct {
	OnStart         ScannerCallbackNoArgFn
	OnStartManifest ScannerCallbackOnManifestFn
	OnStartPackage  ScannerCallbackOnPackageFn
	OnDonePackage   ScannerCallbackOnPackageFn
	OnDoneManifest  ScannerCallbackOnManifestFn
	BeforeFinish    ScannerCallbackNoArgFn
	OnStop          ScannerCallbackNoArgFn
}

func (s *packageManifestScanner) WithCallbacks(callbacks ScannerCallbacks) {
	s.callbacks = callbacks
}

func (s *packageManifestScanner) dispatchOnStart() {
	if s.callbacks.OnStart != nil {
		s.callbacks.OnStart()
	}
}

func (s *packageManifestScanner) dispatchBeforeFinish() {
	if s.callbacks.BeforeFinish != nil {
		s.callbacks.BeforeFinish()
	}
}
