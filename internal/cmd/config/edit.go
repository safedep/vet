package config

import (
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

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
			ed := strings.Fields(editor(a))
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
