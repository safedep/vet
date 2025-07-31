package parser

import (
	scalibrlog "github.com/google/osv-scalibr/log"
)

func init() {
	// Disable osv-scalibr's native logging.
	scalibrlog.SetLogger(silentLogger{})
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
