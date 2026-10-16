package app

import (
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"os"
	"regexp"
	"strings"

	"github.com/safedep/dry/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/output"
)

// LogOptions say where the log lines of vet and of its libraries go. With
// none set, vet drops them. A scan of a large project gives hundreds of
// Scalibr lines, and stdout and the view on stderr must stay clean.
type LogOptions struct {
	// Debug writes the lines at the debug level to stderr.
	Debug bool
	// File appends the lines at the debug level to a file, as JSON.
	File string
}

// InitLog sets the global logger of dry/log, and sends the standard log
// package to it at the debug level. It returns the function that closes the
// log file. dry/log writes its console lines to stdout, which holds the -o
// data of vet, so vet builds its own logger for stderr.
func InitLog(o LogOptions) (func() error, error) {
	var cores []zapcore.Core
	closeFile := func() error { return nil }
	if o.Debug {
		enc := zap.NewDevelopmentEncoderConfig()
		enc.EncodeLevel = zapcore.CapitalLevelEncoder
		cores = append(cores, zapcore.NewCore(zapcore.NewConsoleEncoder(enc), zapcore.AddSync(viewStderr{}), zapcore.DebugLevel))
	}
	if o.File != "" {
		if info, err := os.Lstat(o.File); err == nil && !info.Mode().IsRegular() {
			return nil, UsageError(fmt.Sprintf("--log: %s is not a regular file", o.File), "Name a new file or a regular file. vet does not follow a symbolic link.")
		}
		f, err := os.OpenFile(o.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, UsageError(fmt.Sprintf("--log: %v", err), "Name a file that vet can write.")
		}
		enc := zap.NewProductionEncoderConfig()
		enc.TimeKey, enc.EncodeTime = "timestamp", zapcore.ISO8601TimeEncoder
		cores = append(cores, zapcore.NewCore(zapcore.NewJSONEncoder(enc), zapcore.AddSync(f), zapcore.DebugLevel))
		closeFile = f.Close
	}
	if len(cores) == 0 {
		log.SetGlobal(log.NewNopLogger())
		stdlog.SetOutput(io.Discard)
		return closeFile, nil
	}
	z := zap.New(zapcore.NewTee(cores...)).Sugar().With("service", "vet")
	log.SetGlobal(zapLogger{z})
	stdlog.SetFlags(0)
	stdlog.SetPrefix("")
	stdlog.SetOutput(stdWriter{})
	return func() error { return errors.Join(z.Sync(), closeFile()) }, nil
}

// zapLogger is the dry/log Logger of a zap logger. It cleans each line,
// because a library line can hold a URL with a token and text from the
// scanned repository.
type zapLogger struct{ s *zap.SugaredLogger }

func (z zapLogger) Infof(msg string, args ...any)  { z.s.Info(clean(msg, args)) }
func (z zapLogger) Warnf(msg string, args ...any)  { z.s.Warn(clean(msg, args)) }
func (z zapLogger) Errorf(msg string, args ...any) { z.s.Error(clean(msg, args)) }
func (z zapLogger) Debugf(msg string, args ...any) { z.s.Debug(clean(msg, args)) }
func (z zapLogger) Fatalf(msg string, args ...any) { z.s.Fatal(clean(msg, args)) }

// userInfo is the user and the password of a URL, as in
// https://x-access-token:$TOKEN@github.com.
var userInfo = regexp.MustCompile(`://[^/\s@]+@`)

// clean masks the user and the password of each URL, and escapes the text
// that a terminal would read as a control sequence.
func clean(msg string, args []any) string {
	return escape.Line(userInfo.ReplaceAllString(fmt.Sprintf(msg, args...), "://***@"))
}

func (z zapLogger) With(args map[string]any) log.Logger {
	kv := make([]any, 0, 2*len(args))
	for k, v := range args {
		kv = append(kv, k, v)
	}
	return zapLogger{z.s.With(kv...)}
}

// viewStderr writes to the stderr of the view, so that a test can capture
// the log lines. It has no Sync, because the Sync of a terminal fails with
// EINVAL.
type viewStderr struct{}

func (viewStderr) Write(p []byte) (int, error) { return output.Stderr().Write(p) }

// stdWriter sends a line of the standard log package to dry/log.
type stdWriter struct{}

func (stdWriter) Write(p []byte) (int, error) {
	if msg := strings.TrimRight(string(p), "\n"); msg != "" {
		log.Debugf("%s", msg)
	}
	return len(p), nil
}
