package app

import (
	"bytes"
	"encoding/json"
	"io"
	stdlog "log"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/tui/output"
)

func TestInitLog(t *testing.T) {
	t.Cleanup(func() {
		output.SetWriters(os.Stdout, os.Stderr)
		log.SetGlobal(log.NewNopLogger())
		stdlog.SetOutput(os.Stderr)
	})
	cases := []struct {
		name   string
		debug  bool
		file   bool
		stderr bool
	}{
		{name: "no flag drops the lines"},
		{name: "debug writes stderr", debug: true, stderr: true},
		{name: "log writes the file", file: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			output.SetWriters(&stdout, &stderr)
			o := LogOptions{Debug: tc.debug}
			if tc.file {
				o.File = filepath.Join(t.TempDir(), "vet.log")
			}
			closeLog, err := InitLog(o)
			require.NoError(t, err)
			log.Debugf("read %s", "package-lock.json")
			stdlog.Printf("could not extract %s", "pom.xml")
			require.NoError(t, closeLog())

			assert.Empty(t, stdout.String(), "a log line never goes to stdout")
			if tc.stderr {
				assert.Contains(t, stderr.String(), "DEBUG")
				assert.Contains(t, stderr.String(), "read package-lock.json")
				assert.Contains(t, stderr.String(), "could not extract pom.xml", "the standard log package goes to dry/log")
			} else {
				assert.Empty(t, stderr.String())
			}
			if tc.file {
				b, err := os.ReadFile(o.File)
				require.NoError(t, err)
				line, _, _ := bytes.Cut(b, []byte("\n"))
				var rec map[string]any
				require.NoError(t, json.Unmarshal(line, &rec))
				assert.Equal(t, "read package-lock.json", rec["msg"])
			}
		})
	}
}

func TestInitLogRejectsAnUnwritableFile(t *testing.T) {
	_, err := InitLog(LogOptions{File: filepath.Join(t.TempDir(), "missing", "vet.log")})
	assert.Equal(t, ExitUsage, ExitCode(err))
}

func TestApplyDebug(t *testing.T) {
	t.Cleanup(func() {
		output.SetMode(output.Rich)
		output.SetWriters(os.Stdout, os.Stderr)
		log.SetGlobal(log.NewNopLogger())
		stdlog.SetOutput(os.Stderr)
	})
	output.SetWriters(io.Discard, io.Discard)
	cases := []struct {
		name     string
		quiet    bool
		mode     string
		wantErr  bool
		wantMode output.Mode
	}{
		{name: "debug and quiet conflict", quiet: true, wantErr: true},
		{name: "rich becomes plain, so the log does not break the live progress", wantMode: output.Plain},
		{name: "agent stays agent", mode: "agent", wantMode: output.Agent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output.SetMode(output.Rich)
			a := New(Options{})
			a.Globals.Debug, a.Globals.Quiet, a.Globals.Mode = true, tc.quiet, tc.mode
			err := a.Apply()
			if tc.wantErr {
				assert.Equal(t, ExitUsage, ExitCode(err))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantMode, output.CurrentMode())
			require.NoError(t, a.CloseLog())
		})
	}
}

func TestInitLogCleansEachLine(t *testing.T) {
	t.Cleanup(func() {
		output.SetWriters(os.Stdout, os.Stderr)
		log.SetGlobal(log.NewNopLogger())
		stdlog.SetOutput(os.Stderr)
	})
	var stderr bytes.Buffer
	output.SetWriters(io.Discard, &stderr)
	closeLog, err := InitLog(LogOptions{Debug: true})
	require.NoError(t, err)
	log.Debugf("clone %s", "https://x-access-token:s3cr3t-t0ken@github.com/org/repo.git") // trufflehog:ignore
	log.Debugf("Invalid spec line: %s", "evil\x1b[31m")
	require.NoError(t, closeLog())

	assert.NotContains(t, stderr.String(), "s3cr3t-t0ken", "a library line never prints the token of a URL")
	assert.Contains(t, stderr.String(), "https://***@github.com/org/repo.git")
	assert.NotContains(t, stderr.String(), "\x1b[31m", "a control sequence from a repository is escaped")
}

func TestInitLogRefusesASymbolicLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim.txt")
	require.NoError(t, os.WriteFile(target, []byte("keep\n"), 0o644))
	link := filepath.Join(dir, "vet.log")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symbolic links: %v", err)
	}
	_, err := InitLog(LogOptions{File: link})
	assert.Equal(t, ExitUsage, ExitCode(err))
	b, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "keep\n", string(b), "vet does not write through the link")
}
