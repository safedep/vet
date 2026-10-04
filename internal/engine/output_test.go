package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

// countSink writes the number of records, and fails after a partial write
// when fail is set.
type countSink struct{ fail bool }

func (s countSink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	n := 0
	for _, err := range r.Records(ctx) {
		if err != nil {
			return err
		}
		n++
	}
	if _, err := io.WriteString(w, "records "); err != nil {
		return err
	}
	if s.fail {
		return errors.New("disk full")
	}
	_, err := io.WriteString(w, strconv.Itoa(n)+"\n")
	return err
}

// lineSink is a StreamSink that writes one line for each part.
type lineSink struct{ countSink }

func (lineSink) Begin(_ context.Context, h *report.Header, w io.Writer) error {
	_, err := io.WriteString(w, "begin "+h.Tool.Name+"\n")
	return err
}

func (lineSink) Record(_ context.Context, r *report.Record, w io.Writer) error {
	_, err := io.WriteString(w, string(r.Kind)+"\n")
	return err
}

func (lineSink) End(_ context.Context, t *report.Trailer, w io.Writer) error {
	_, err := io.WriteString(w, "end "+string(t.Gate.Outcome)+"\n")
	return err
}

func TestWriteOutputs(t *testing.T) {
	r := plugintest.SampleReport()
	dir := t.TempDir()
	file := filepath.Join(dir, "report.txt")
	var stdout bytes.Buffer
	err := WriteOutputs(context.Background(), r, []Output{
		{Format: "count", Sink: countSink{}},
		{Format: "count", Path: file, Sink: countSink{}},
		{Format: "lines", Path: filepath.Join(dir, "lines.txt"), Sink: lineSink{}},
	}, &stdout)
	require.NoError(t, err)

	n := 0
	for range r.Records(context.Background()) {
		n++
	}
	want := "records " + strconv.Itoa(n) + "\n"
	assert.Equal(t, want, stdout.String())
	b, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Equal(t, want, string(b))

	lines, err := os.ReadFile(filepath.Join(dir, "lines.txt"))
	require.NoError(t, err)
	assert.Contains(t, string(lines), "begin vet\n")
	assert.Contains(t, string(lines), "end "+string(r.Trailer().Gate.Outcome)+"\n")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 2, "no temporary file stays")
}

func TestWriteOutputsFailure(t *testing.T) {
	r := plugintest.SampleReport()
	dir := t.TempDir()
	file := filepath.Join(dir, "report.txt")
	require.NoError(t, os.WriteFile(file, []byte("old"), 0o600))

	cases := []struct {
		name string
		out  Output
	}{
		{name: "the sink fails", out: Output{Format: "count", Path: file, Sink: countSink{fail: true}}},
		{name: "no directory", out: Output{Format: "count", Path: filepath.Join(dir, "missing", "r.txt"), Sink: countSink{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := WriteOutputs(context.Background(), r, []Output{tc.out}, io.Discard)
			require.Error(t, err)
			ue, ok := usefulerror.AsUsefulError(err)
			require.True(t, ok)
			assert.Equal(t, CodeReportWrite, ue.Code())
			assert.Equal(t, app.ExitRuntime, app.ExitCode(err))

			b, err := os.ReadFile(file)
			require.NoError(t, err)
			assert.Equal(t, "old", string(b), "a failed write keeps the old file")
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			assert.Len(t, entries, 1, "no partial file stays")
		})
	}
}
