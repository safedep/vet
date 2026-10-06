package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/safedep/dry/usefulerror"

	"github.com/safedep/vet/v2/plugin"
)

// CodeReportWrite is the error code of a report that vet could not write.
// The command exits with code 3.
const CodeReportWrite = "report_write_failed"

// Output is one destination of a report: stdout for -o, or a file for
// --report.
type Output struct {
	Format string
	// Path is the file, or "" for stdout.
	Path string
	// Publish is true when the sink publishes the report itself.
	// WriteOutputs skips it, and Publish runs it.
	Publish bool
	Sink    plugin.Sink
}

// WriteOutputs writes the report to each destination. A file destination
// gets a temporary file in its directory that vet renames into place, so
// a failed write leaves no partial file and keeps the file that was there.
func WriteOutputs(ctx context.Context, r plugin.Report, outs []Output, stdout io.Writer) error {
	for _, o := range outs {
		if o.Publish {
			continue
		}
		var err error
		if o.Path == "" {
			err = writeSink(ctx, o.Sink, r, stdout)
		} else {
			err = writeFile(ctx, o, r)
		}
		if err != nil {
			return writeError(o, err)
		}
	}
	return nil
}

func writeSink(ctx context.Context, s plugin.Sink, r plugin.Report, w io.Writer) error {
	ss, ok := s.(plugin.StreamSink)
	if !ok {
		return s.Write(ctx, r, w)
	}
	if err := ss.Begin(ctx, r.Header(), w); err != nil {
		return err
	}
	for rec, err := range r.Records(ctx) {
		if err != nil {
			return err
		}
		if err := ss.Record(ctx, rec, w); err != nil {
			return err
		}
	}
	return ss.End(ctx, r.Trailer(), w)
}

func writeFile(ctx context.Context, o Output, r plugin.Report) (err error) {
	dir, base := filepath.Split(o.Path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, removeTemp(tmp.Name()))
		}
	}()
	if err := writeSink(ctx, o.Sink, r, tmp); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), o.Path)
}

func removeTemp(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func writeError(o Output, err error) error {
	dest := "stdout"
	if o.Path != "" {
		dest = o.Path
	}
	msg := fmt.Sprintf("write the %s report to %s: %v", o.Format, dest, err)
	return usefulerror.NewUsefulError().
		WithCode(CodeReportWrite).
		WithHumanError(msg).
		WithHelp("Check that the directory exists and that you can write to it. The scan is saved. vet report show writes it again.").
		WithMsg(msg)
}
