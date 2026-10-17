package extractors

import (
	"fmt"

	scalibrlog "github.com/google/osv-scalibr/log"
	"github.com/safedep/dry/log"
)

// CaptureLogs sends the log lines of Scalibr and of the extractors to
// dry/log at the debug level. The default Scalibr logger prints each
// malformed file to stderr, and a scan reports such a file as a diagnostic.
func CaptureLogs() { scalibrlog.SetLogger(logger{}) }

type logger struct{}

func (logger) Errorf(format string, args ...any) { log.Debugf(format, args...) }
func (logger) Error(args ...any)                 { log.Debugf("%s", fmt.Sprint(args...)) }
func (logger) Warnf(format string, args ...any)  { log.Debugf(format, args...) }
func (logger) Warn(args ...any)                  { log.Debugf("%s", fmt.Sprint(args...)) }
func (logger) Infof(format string, args ...any)  { log.Debugf(format, args...) }
func (logger) Info(args ...any)                  { log.Debugf("%s", fmt.Sprint(args...)) }
func (logger) Debugf(format string, args ...any) { log.Debugf(format, args...) }
func (logger) Debug(args ...any)                 { log.Debugf("%s", fmt.Sprint(args...)) }
