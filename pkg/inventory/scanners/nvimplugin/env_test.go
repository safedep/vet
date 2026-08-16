package nvimplugin

import (
	"path/filepath"
	"testing"

	"github.com/safedep/vet/pkg/inventory"
)

func TestResolveEnv_HomeDirPrecedence(t *testing.T) {
	// XDG env is set, but cfg.HomeDir must win and derive paths from home.
	t.Setenv("XDG_CONFIG_HOME", "/should/be/ignored")
	t.Setenv("XDG_DATA_HOME", "/should/be/ignored")
	t.Setenv("NVIM_APPNAME", "")

	home := t.TempDir()
	env, err := resolveEnv(inventory.ScanConfig{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".config", "nvim"); env.ConfigDir != want {
		t.Errorf("ConfigDir = %q, want %q", env.ConfigDir, want)
	}
	if want := filepath.Join(home, ".local", "share", "nvim"); env.DataDir != want {
		t.Errorf("DataDir = %q, want %q", env.DataDir, want)
	}
}

func TestResolveEnv_NvimAppName(t *testing.T) {
	t.Setenv("NVIM_APPNAME", "myapp")
	home := t.TempDir()

	env, err := resolveEnv(inventory.ScanConfig{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".config", "myapp"); env.ConfigDir != want {
		t.Errorf("ConfigDir = %q, want %q", env.ConfigDir, want)
	}
	if want := filepath.Join(home, ".local", "share", "myapp"); env.DataDir != want {
		t.Errorf("DataDir = %q, want %q", env.DataDir, want)
	}
}

func TestComputePaths_PosixXDGOverride(t *testing.T) {
	configDir, dataDir := computePaths("linux", "/home/u", "/xc", "/xd", "", "nvim")
	if configDir != "/xc/nvim" {
		t.Errorf("ConfigDir = %q, want /xc/nvim", configDir)
	}
	if dataDir != "/xd/nvim" {
		t.Errorf("DataDir = %q, want /xd/nvim", dataDir)
	}
}

func TestComputePaths_PosixDefault(t *testing.T) {
	configDir, dataDir := computePaths("linux", "/home/u", "", "", "", "nvim")
	if want := filepath.Join("/home/u", ".config", "nvim"); configDir != want {
		t.Errorf("ConfigDir = %q, want %q", configDir, want)
	}
	if want := filepath.Join("/home/u", ".local", "share", "nvim"); dataDir != want {
		t.Errorf("DataDir = %q, want %q", dataDir, want)
	}
}

func TestComputePaths_Windows(t *testing.T) {
	configDir, dataDir := computePaths("windows", `C:\Users\u`, "", "", `C:\Users\u\AppData\Local`, "nvim")
	if want := filepath.Join(`C:\Users\u\AppData\Local`, "nvim"); configDir != want {
		t.Errorf("ConfigDir = %q, want %q", configDir, want)
	}
	if want := filepath.Join(`C:\Users\u\AppData\Local`, "nvim-data"); dataDir != want {
		t.Errorf("DataDir = %q, want %q", dataDir, want)
	}
}

func TestComputePaths_WindowsAppNameStem(t *testing.T) {
	_, dataDir := computePaths("windows", `C:\Users\u`, "", "", `C:\LA`, "myapp")
	if want := filepath.Join(`C:\LA`, "myapp-data"); dataDir != want {
		t.Errorf("DataDir = %q, want %q", dataDir, want)
	}
}
