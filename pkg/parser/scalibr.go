package parser

import (
	"github.com/google/osv-scalibr/binary/platform"
	scalibrfs "github.com/google/osv-scalibr/fs"

	scalibrlog "github.com/google/osv-scalibr/log"
)

func init() {
	// Disable osv-scalibr's native logging.
	scalibrlog.SetLogger(silentLogger{})
}

// scanRoots function returns the default scan root required for osv-scalibr
// Default is `/`
func scanRoots() ([]*scalibrfs.ScanRoot, error) {
	var scanRoots []*scalibrfs.ScanRoot
	var scanRootPaths []string
	var err error
	if scanRootPaths, err = platform.DefaultScanRoots(false); err != nil {
		return nil, err
	}
	for _, r := range scanRootPaths {
		scanRoots = append(scanRoots, &scalibrfs.ScanRoot{FS: scalibrfs.DirFS(r), Path: r})
	}
	return scanRoots, nil
}

// silentLogger is custom logger for osv-scalibr
// Primarily used to ignore / mute the osv-scalibr's native logging
type silentLogger struct{}

func (silentLogger) Errorf(format string, args ...any) {}
func (silentLogger) Error(args ...any)                 {}
func (silentLogger) Warnf(format string, args ...any)  {}
func (silentLogger) Warn(args ...any)                  {}
func (silentLogger) Infof(format string, args ...any)  {}
func (silentLogger) Info(args ...any)                  {}
func (silentLogger) Debugf(format string, args ...any) {}
func (silentLogger) Debug(args ...any)                 {}
