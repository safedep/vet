package config

import (
	"os/exec"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
)

func TestEditor(t *testing.T) {
	fallback := "vi"
	if runtime.GOOS == "windows" {
		fallback = "notepad"
	}
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"visual wins", map[string]string{"VISUAL": "code --wait", "EDITOR": "nano"}, "code --wait"},
		{"editor", map[string]string{"EDITOR": "nano"}, "nano"},
		{"blank visual", map[string]string{"VISUAL": "  ", "EDITOR": "nano"}, "nano"},
		{"none", nil, fallback},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := app.New(app.Options{LookupEnv: func(k string) (string, bool) {
				v, ok := tc.env[k]
				return v, ok
			}})
			assert.Equal(t, tc.want, editor(a))
		})
	}
}

func TestEditorCommand(t *testing.T) {
	notFound := func(string) (string, error) { return "", exec.ErrNotFound }
	getenv := func(k string) string { return map[string]string{"HOME": "/home/u"}[k] }
	cases := []struct {
		name, value, goos string
		lookPath          func(string) (string, error)
		want              []string
	}{
		{"program and argument", "code --wait", "linux", notFound, []string{"code", "--wait"}},
		{"posix quotes", `"/opt/my editor/bin/ed" -w`, "darwin", notFound, []string{"/opt/my editor/bin/ed", "-w"}},
		{"windows path with a space", `C:\Program Files\Vim\gvim.exe`, "windows", func(string) (string, error) { return "", nil }, []string{`C:\Program Files\Vim\gvim.exe`}},
		{"windows quotes keep backslashes", `"C:\Program Files\Code\code.exe" --wait`, "windows", notFound, []string{`C:\Program Files\Code\code.exe`, "--wait"}},
		{"windows plain", `C:\tools\vim.exe -f`, "windows", notFound, []string{`C:\tools\vim.exe`, "-f"}},
		{"posix variable", "$HOME/bin/ed -w", "linux", notFound, []string{"/home/u/bin/ed", "-w"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := editorCommand(tc.value, tc.goos, tc.lookPath, getenv)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
	_, err := editorCommand("  ", "linux", notFound, getenv)
	assert.Error(t, err, "a blank value names no program")
}
