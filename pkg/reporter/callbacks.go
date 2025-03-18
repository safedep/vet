package reporter

import (
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/models"
)

// SyncReporterCallbacks are effects trigger during Cloud Sync Report Process
// This is primarily used to show progress bar on the terminal
type SyncReporterCallbacks struct {
	OnPackageSync     func(pkg *models.Package)
	OnPackageSyncDone func(pkg *models.Package)
	OnEventSync       func(event *analyzer.AnalyzerEvent)
	OnEventSyncDone   func(event *analyzer.AnalyzerEvent)
	OnSyncFinish      func()
}

func (s *syncReporter) dispatchOnPackageSync(pkg *models.Package) {
	if s.callbacks.OnPackageSync != nil {
		s.callbacks.OnPackageSync(pkg)
	}
}

func (s *syncReporter) dispatchOnPackageSyncDone(pkg *models.Package) {
	if s.callbacks.OnPackageSyncDone != nil {
		s.callbacks.OnPackageSyncDone(pkg)
	}
}

func (s *syncReporter) dispatchOnEventSync(event *analyzer.AnalyzerEvent) {
	if s.callbacks.OnEventSync != nil {
		s.callbacks.OnEventSync(event)
	}
}

func (s *syncReporter) dispatchOnEventSyncDone(event *analyzer.AnalyzerEvent) {
	if s.callbacks.OnEventSyncDone != nil {
		s.callbacks.OnEventSyncDone(event)
	}
}

func (s *syncReporter) dispatchOnSyncFinish() {
	if s.callbacks.OnSyncFinish != nil {
		s.callbacks.OnSyncFinish()
	}
}
