package config

import (
	"path/filepath"

	"github.com/safedep/vet/v2/internal/config/appdir"
)

// FileName is the name of the config file in the config and managed directories.
const FileName = "config.yml"

// Tool is the name of the tool in the safedep/<tool> namespace.
const Tool = "vet"

// BootstrapOptions are the inputs of Bootstrap.
type BootstrapOptions struct {
	// ConfigFile is the file of --config.
	ConfigFile string
	// StateDir and CacheDir are the flags --state-dir and --cache-dir.
	StateDir, CacheDir string
	// Flags maps a key to the raw value of the flag that sets it.
	Flags map[string]string
	// LookupEnv reads a variable. It defaults to os.LookupEnv.
	LookupEnv func(string) (string, bool)
	// Environ and PluginNames are for the VET_PLUGINS_* variables. See
	// LoadOptions.
	Environ     func() []string
	PluginNames []string
	// TrustManaged checks the managed file. It defaults to ManagedFileTrusted.
	TrustManaged func(string) bool
	// DirOptions change how the directories resolve, for tests.
	DirOptions []appdir.Option
}

// Runtime is the effective config and the directories of one run.
type Runtime struct {
	*Loaded
	Dirs appdir.Dirs
}

// Bootstrap resolves the config directory, loads the config from its
// layers, and then resolves the state and cache directories, which the
// config file can set.
func Bootstrap(opts BootstrapOptions) (*Runtime, error) {
	dirOpts := append([]appdir.Option{}, opts.DirOptions...)
	if opts.LookupEnv != nil {
		dirOpts = append(dirOpts, appdir.WithLookupEnv(opts.LookupEnv))
	}

	first, err := appdir.Resolve(Tool, dirOpts...)
	if err != nil {
		return nil, err
	}

	loaded, err := Load(LoadOptions{
		ManagedFile:  filepath.Join(first.Managed, FileName),
		ConfigFile:   opts.ConfigFile,
		UserFile:     filepath.Join(first.Config, FileName),
		Flags:        opts.Flags,
		LookupEnv:    opts.LookupEnv,
		Environ:      opts.Environ,
		PluginNames:  opts.PluginNames,
		TrustManaged: opts.TrustManaged,
	})
	if err != nil {
		return nil, err
	}

	dirOpts = append(dirOpts,
		appdir.WithOverride(appdir.State, opts.StateDir),
		appdir.WithOverride(appdir.Cache, opts.CacheDir),
		appdir.WithConfigKey(appdir.State, loaded.Config.State.Dir),
		appdir.WithConfigKey(appdir.Cache, loaded.Config.Cache.Dir),
	)
	dirs, err := appdir.Resolve(Tool, dirOpts...)
	if err != nil {
		return nil, err
	}
	return &Runtime{Loaded: loaded, Dirs: dirs}, nil
}

// UserFile returns the path of the user config file.
func (r *Runtime) UserFile() string { return filepath.Join(r.Dirs.Config, FileName) }

// ManagedFile returns the path of the managed config file.
func (r *Runtime) ManagedFile() string { return filepath.Join(r.Dirs.Managed, FileName) }
