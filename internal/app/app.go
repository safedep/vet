// Package app holds what every vet command shares: the global flags, the
// config of the run and the data printer. The command packages under
// internal/cmd do not import each other, so they share it through this
// package.
package app

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/safedep/dry/usefulerror"

	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/printer"
	"github.com/safedep/vet/v2/internal/tui/prompt"
)

// Globals are the global flags: -o, --mode, -v, -q, --no-input, --config
// and --profile. Every other flag is local to its command.
type Globals struct {
	Output     string
	Mode       string
	Verbose    bool
	Quiet      bool
	NoInput    bool
	ConfigFile string
	Profile    string
}

// Options build an App.
type Options struct {
	// LookupEnv reads a variable. It defaults to os.LookupEnv.
	LookupEnv func(string) (string, bool)
	// Environ lists the variables. It defaults to os.Environ.
	Environ func() []string
	// PluginNames are the built-in plugins, for the VET_PLUGINS_* variables.
	PluginNames []string
	// Bootstrap changes how the config loads, for tests.
	Bootstrap config.BootstrapOptions
}

// App is the shared context of one vet run.
type App struct {
	Globals Globals

	opts    Options
	once    sync.Once
	runtime *config.Runtime
	err     error
}

// New returns an App.
func New(o Options) *App {
	if o.Environ == nil {
		o.Environ = os.Environ
	}
	if o.LookupEnv == nil {
		o.LookupEnv = os.LookupEnv
	}
	return &App{opts: o}
}

// LookupEnv reads a variable.
func (a *App) LookupEnv(key string) (string, bool) { return a.opts.LookupEnv(key) }

var modes = map[string]output.Mode{"rich": output.Rich, "plain": output.Plain, "agent": output.Agent}

// Apply checks the global flags and sets the messaging mode and the
// verbosity. The root command calls it before every command.
func (a *App) Apply() error {
	g := a.Globals
	if g.Verbose && g.Quiet {
		return UsageError("-v and -q cannot be used together", "Use -v for more output or -q for less output.")
	}
	if err := setMode(g.Mode, "--mode"); err != nil {
		return err
	}
	prompt.SetNoInput(g.NoInput)
	switch {
	case g.Verbose:
		output.SetVerbosity(output.Verbose)
	case g.Quiet:
		output.SetVerbosity(output.Silent)
	default:
		output.SetVerbosity(output.Normal)
	}
	return nil
}

func setMode(mode, from string) error {
	if mode == "" || mode == "auto" {
		return nil
	}
	m, ok := modes[mode]
	if !ok {
		return UsageError(fmt.Sprintf("%s: unknown mode %q", from, mode), "Use auto, rich, plain or agent.")
	}
	output.SetMode(m)
	return nil
}

// ConfigOptions are the local flags that change the config of a run.
type ConfigOptions struct {
	StateDir, CacheDir string
}

func (o ConfigOptions) dirKeys() []string {
	var keys []string
	if o.StateDir != "" {
		keys = append(keys, "state.dir")
	}
	if o.CacheDir != "" {
		keys = append(keys, "cache.dir")
	}
	return keys
}

// Config loads the config of the run once: the defaults, the config files,
// the VET_* variables and the flags. A config mode applies when --mode is
// not set.
func (a *App) Config(o ConfigOptions) (*config.Runtime, error) {
	a.once.Do(func() {
		b := a.opts.Bootstrap
		b.ConfigFile = a.Globals.ConfigFile
		b.StateDir, b.CacheDir = o.StateDir, o.CacheDir
		if b.LookupEnv == nil {
			b.LookupEnv = a.opts.LookupEnv
		}
		if b.Environ == nil {
			b.Environ = a.opts.Environ
		}
		if b.PluginNames == nil {
			b.PluginNames = a.opts.PluginNames
		}
		b.Flags = map[string]string{}
		if a.Globals.Mode != "" {
			b.Flags["output.mode"] = a.Globals.Mode
		}
		if a.Globals.Profile != "" {
			b.Flags["cloud.profile"] = a.Globals.Profile
		}
		a.runtime, a.err = config.Bootstrap(b)
		if a.err == nil {
			a.err = a.runtime.RefuseLocked(o.dirKeys()...)
		}
		if a.err == nil && a.Globals.Mode == "" {
			a.err = setMode(a.runtime.Config.Output.Mode, "output.mode")
		}
	})
	return a.runtime, a.err
}

// Printer returns the data printer for -o. Without -o it picks the format
// from the messaging mode.
func (a *App) Printer() (*printer.Printer, error) {
	if a.Globals.Output == "" {
		return printer.New(printer.DefaultFormat(output.CurrentMode())), nil
	}
	f, err := printer.ParseFormat(a.Globals.Output)
	if err != nil {
		return nil, UsageError(fmt.Sprintf("-o: %v", err), "Use table, plain, json or jsonl.")
	}
	return printer.New(f), nil
}

// CodeNeedsConfirmation is the error code of a command that needs a
// confirmation in agent mode or with --no-input. The command exits with
// code 2.
const CodeNeedsConfirmation = "usage_needs_confirmation"

// Confirm asks a yes or no question. In agent mode or with --no-input it
// does not wait for input. It returns a usage error that names the flag
// that answers the question.
func (a *App) Confirm(label, flag string) (bool, error) {
	ok, err := prompt.Confirm(label, false)
	if errors.Is(err, prompt.ErrAgentMode) || errors.Is(err, prompt.ErrNoTTY) {
		msg := fmt.Sprintf("vet cannot ask %q in this mode", label)
		return false, usefulerror.NewUsefulError().WithCode(CodeNeedsConfirmation).
			WithHumanError(msg).WithHelp(fmt.Sprintf("Pass %s to confirm.", flag)).WithMsg(msg)
	}
	return ok, err
}
