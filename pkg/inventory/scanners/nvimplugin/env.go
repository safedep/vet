package nvimplugin

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/safedep/vet/pkg/inventory"
)

// Env is the resolved Neovim path layout, computed once per scan and
// shared by every manager.
type Env struct {
	HomeDir   string // resolved user home
	ConfigDir string // stdpath("config"), e.g. ~/.config/nvim
	DataDir   string // stdpath("data"),   e.g. ~/.local/share/nvim
}

// defaultAppName is the config/data stem when NVIM_APPNAME is unset.
const defaultAppName = "nvim"

// resolveEnv computes the Neovim path layout, mirroring stdpath().
// cfg.HomeDir, when set, wins over process XDG variables and derives
// ~/.config and ~/.local/share from it (this is what makes the scanner
// testable); otherwise the OS home is used with $XDG_* honored.
// NVIM_APPNAME substitutes for the "nvim" path component either way.
func resolveEnv(cfg inventory.ScanConfig) (Env, error) {
	home := cfg.HomeDir
	var xdgConfig, xdgData, localAppData string
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return Env{}, err
		}
		home = h
		xdgConfig = os.Getenv("XDG_CONFIG_HOME")
		xdgData = os.Getenv("XDG_DATA_HOME")
		localAppData = os.Getenv("LOCALAPPDATA")
	}

	appName := os.Getenv("NVIM_APPNAME")
	if appName == "" {
		appName = defaultAppName
	}

	configDir, dataDir := computePaths(runtime.GOOS, home, xdgConfig, xdgData, localAppData, appName)
	return Env{HomeDir: home, ConfigDir: configDir, DataDir: dataDir}, nil
}

// computePaths derives the config and data directories for a given OS and
// base-path inputs. Split out of resolveEnv so both layouts are testable
// on any host.
func computePaths(goos, home, xdgConfig, xdgData, localAppData, appName string) (configDir, dataDir string) {
	if goos == "windows" {
		base := localAppData
		if base == "" {
			base = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(base, appName), filepath.Join(base, appName+"-data")
	}

	configBase := xdgConfig
	if configBase == "" {
		configBase = filepath.Join(home, ".config")
	}
	dataBase := xdgData
	if dataBase == "" {
		dataBase = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(configBase, appName), filepath.Join(dataBase, appName)
}
