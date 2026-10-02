// Package appdir resolves the config, state, cache and managed config
// directories of one SafeDep tool. It has the API that dry/appdir will
// have, so the move to dry is a copy (decisions D17).
package appdir

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// Kind names one kind of directory.
type Kind string

const (
	Config  Kind = "config"
	State   Kind = "state"
	Cache   Kind = "cache"
	Managed Kind = "managed"
)

// Dirs holds the four directories of a tool.
type Dirs struct {
	Config, State, Cache, Managed string
	// Origin names the rule that chose each directory.
	Origin map[Kind]string
}

// Get returns the directory of a kind.
func (d Dirs) Get(k Kind) string {
	switch k {
	case Config:
		return d.Config
	case State:
		return d.State
	case Cache:
		return d.Cache
	case Managed:
		return d.Managed
	}
	return ""
}

type options struct {
	overrides  map[Kind]string
	configKeys map[Kind]string
	lookupEnv  func(string) (string, bool)
	goos       string
	home       string
	euid       int
	rootHome   string
}

// Option changes how Resolve works.
type Option func(*options)

// WithOverride sets a directory from a flag. It wins over every other rule.
func WithOverride(k Kind, path string) Option {
	return func(o *options) {
		if path != "" {
			o.overrides[k] = path
		}
	}
}

// WithConfigKey sets the state or cache directory from the config file.
func WithConfigKey(k Kind, path string) Option {
	return func(o *options) {
		if path != "" {
			o.configKeys[k] = path
		}
	}
}

// WithLookupEnv replaces os.LookupEnv, for tests.
func WithLookupEnv(fn func(string) (string, bool)) Option {
	return func(o *options) { o.lookupEnv = fn }
}

// WithPlatform replaces the OS, the home directory, the effective user id and
// root's home directory, for tests.
func WithPlatform(goos, home string, euid int, rootHome string) Option {
	return func(o *options) {
		o.goos, o.home, o.euid, o.rootHome = goos, home, euid, rootHome
	}
}

// Resolve returns the directories of a tool under the safedep/<tool>
// namespace. For config, state and cache it takes the first rule that
// applies: the flag, the <TOOL>_<KIND>_DIR variable, the config key (state
// and cache only), root's directory under sudo, the XDG variable when it is
// an absolute path, and the platform default.
func Resolve(tool string, opts ...Option) (Dirs, error) {
	o := &options{
		overrides:  map[Kind]string{},
		configKeys: map[Kind]string{},
		lookupEnv:  os.LookupEnv,
		goos:       runtime.GOOS,
		euid:       os.Geteuid(),
	}
	for _, opt := range opts {
		opt(o)
	}
	if o.home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return Dirs{}, fmt.Errorf("find the home directory: %w", err)
		}
		o.home = h
	}
	if o.rootHome == "" {
		o.rootHome = "/root"
		if u, err := user.Lookup("root"); err == nil && u.HomeDir != "" {
			o.rootHome = u.HomeDir
		}
	}

	d := Dirs{Origin: map[Kind]string{}}
	for _, k := range []Kind{Config, State, Cache} {
		path, origin, err := o.resolve(tool, k)
		if err != nil {
			return Dirs{}, err
		}
		d.set(k, path, origin)
	}
	d.set(Managed, o.managed(tool), "platform")
	return d, nil
}

func (d *Dirs) set(k Kind, path, origin string) {
	switch k {
	case Config:
		d.Config = path
	case State:
		d.State = path
	case Cache:
		d.Cache = path
	case Managed:
		d.Managed = path
	}
	d.Origin[k] = origin
}

func (o *options) env(name string) string {
	v, ok := o.lookupEnv(name)
	if !ok {
		return ""
	}
	return v
}

func (o *options) resolve(tool string, k Kind) (string, string, error) {
	if p := o.overrides[k]; p != "" {
		return clean(p), "flag", nil
	}
	name := strings.ToUpper(tool) + "_" + strings.ToUpper(string(k)) + "_DIR"
	if p := o.env(name); p != "" {
		return clean(p), "env " + name, nil
	}
	if p := o.configKeys[k]; p != "" && k != Config {
		return clean(p), "config " + string(k) + ".dir", nil
	}

	if o.goos == "windows" {
		return o.windows(tool, k)
	}

	home := o.home
	if o.euid == 0 && o.env("SUDO_USER") != "" {
		// sudo can keep the user's HOME and XDG variables. A root run must
		// not create root-owned files in the user's home.
		return o.unixDefault(tool, k, o.rootHome), "sudo", nil
	}

	xdg := map[Kind]string{Config: "XDG_CONFIG_HOME", State: "XDG_STATE_HOME", Cache: "XDG_CACHE_HOME"}[k]
	if p := o.env(xdg); p != "" && filepath.IsAbs(p) {
		return filepath.Join(p, "safedep", tool), "env " + xdg, nil
	}
	return o.unixDefault(tool, k, home), "default", nil
}

func (o *options) unixDefault(tool string, k Kind, home string) string {
	switch k {
	case Config:
		return filepath.Join(home, ".config", "safedep", tool)
	case State:
		return filepath.Join(home, ".local", "state", "safedep", tool)
	default:
		if o.goos == "darwin" {
			return filepath.Join(home, "Library", "Caches", "safedep", tool)
		}
		return filepath.Join(home, ".cache", "safedep", tool)
	}
}

func (o *options) windows(tool string, k Kind) (string, string, error) {
	switch k {
	case Config:
		base := o.env("AppData")
		if base == "" {
			base = filepath.Join(o.home, "AppData", "Roaming")
		}
		return filepath.Join(base, "safedep", tool), "default", nil
	default:
		base := o.env("LocalAppData")
		if base == "" {
			base = filepath.Join(o.home, "AppData", "Local")
		}
		return filepath.Join(base, "safedep", tool, string(k)), "default", nil
	}
}

func (o *options) managed(tool string) string {
	switch o.goos {
	case "windows":
		base := o.env("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "safedep", tool)
	case "darwin":
		return filepath.Join("/Library", "Application Support", "safedep", tool)
	default:
		return filepath.Join("/etc", "safedep", tool)
	}
}

func clean(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return filepath.Clean(p)
}

// Ensure creates a directory with mode 0700 when vet first writes there.
func Ensure(path string) error {
	if path == "" {
		return errors.New("appdir: empty directory path")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create directory %s: %w", path, err)
	}
	return nil
}
