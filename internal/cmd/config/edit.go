package config

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"mvdan.cc/sh/v3/shell"

	"github.com/safedep/vet/v2/internal/app"
	vconfig "github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/config/appdir"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/internal/tui/output"
)

func newEdit(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "edit",
		Short: "Open the user config file in an editor",
		Long: `Open the user config file, or the --config file, in $VISUAL or $EDITOR,
then check it. The file keeps every comment. In agent mode or with
--no-input, vet cannot open an editor and exits 2.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.Globals.NoInput || output.CurrentMode() == output.Agent {
				return app.UsageError("vet config edit needs a terminal", "Use vet config set KEY VALUE.")
			}
			_, path, err := target(a)
			if err != nil {
				return err
			}
			if err := appdir.Ensure(dirOf(path)); err != nil {
				return err
			}
			if _, err := os.Stat(path); os.IsNotExist(err) {
				if err := os.WriteFile(path, []byte("# vet config. vet config schema get prints the keys.\n"), 0o600); err != nil {
					return err
				}
			}
			getenv := func(k string) string { v, _ := a.LookupEnv(k); return v }
			ed, err := editorCommand(editor(a), runtime.GOOS, exec.LookPath, getenv)
			if err != nil {
				return app.UsageError(fmt.Sprintf("vet cannot read the editor command: %v", err), "Set $VISUAL or $EDITOR to a program and its arguments.")
			}
			c := exec.CommandContext(cmd.Context(), ed[0], append(ed[1:], path)...)
			c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
			if err := c.Run(); err != nil {
				return err
			}
			l, err := vconfig.Load(vconfig.LoadOptions{ConfigFile: path, LookupEnv: func(string) (string, bool) { return "", false }})
			if err != nil {
				return err
			}
			if err := l.ValidateStrict(); err != nil {
				return err
			}
			tui.Success("%s is valid.", path)
			return nil
		},
	}
}

// editor returns the editor command. It can have arguments, such as
// "code --wait".
func editor(a *app.App) string {
	for _, k := range []string{"VISUAL", "EDITOR"} {
		if v, ok := a.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	if runtime.GOOS == "windows" {
		return "notepad"
	}
	return "vi"
}

// editorCommand splits the editor value into a program and its arguments.
// A value that is one program, such as C:\Program Files\Vim\gvim.exe, stays
// whole. A Windows value splits on spaces outside double quotes and keeps
// each backslash. Another value splits as a POSIX shell word list, as git
// does with $EDITOR, and getenv expands its variables.
func editorCommand(v, goos string, lookPath func(string) (string, error), getenv func(string) string) ([]string, error) {
	if _, err := lookPath(v); err == nil {
		return []string{v}, nil
	}
	var fields []string
	if goos == "windows" {
		fields = windowsFields(v)
	} else {
		var err error
		if fields, err = shell.Fields(v, getenv); err != nil {
			return nil, err
		}
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("%q names no program", v)
	}
	return fields, nil
}

// windowsFields splits a command line on spaces and tabs outside double
// quotes, and drops the quotes.
func windowsFields(v string) []string {
	var fields []string
	var cur strings.Builder
	quoted, started := false, false
	for _, r := range v {
		switch {
		case r == '"':
			quoted, started = !quoted, true
		case (r == ' ' || r == '\t') && !quoted:
			if started {
				fields = append(fields, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if started {
		fields = append(fields, cur.String())
	}
	return fields
}
