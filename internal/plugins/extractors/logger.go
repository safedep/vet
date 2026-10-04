package extractors

import (
	"fmt"

	scalibrlog "github.com/google/osv-scalibr/log"
)

// CaptureLogs sends the log lines of Scalibr and of the extractors to emit.
// The default Scalibr logger prints each malformed file to stderr.
func CaptureLogs(emit func(string)) { scalibrlog.SetLogger(logger{emit}) }

type logger struct{ emit func(string) }

func (l logger) Errorf(format string, args ...any) { l.emit(fmt.Sprintf(format, args...)) }
func (l logger) Error(args ...any)                 { l.emit(fmt.Sprint(args...)) }
func (l logger) Warnf(format string, args ...any)  { l.emit(fmt.Sprintf(format, args...)) }
func (l logger) Warn(args ...any)                  { l.emit(fmt.Sprint(args...)) }
func (l logger) Infof(format string, args ...any)  { l.emit(fmt.Sprintf(format, args...)) }
func (l logger) Info(args ...any)                  { l.emit(fmt.Sprint(args...)) }
func (l logger) Debugf(format string, args ...any) { l.emit(fmt.Sprintf(format, args...)) }
func (l logger) Debug(args ...any)                 { l.emit(fmt.Sprint(args...)) }
