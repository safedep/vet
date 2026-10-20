package codeusage

import (
	"cmp"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/safedep/dry/log"
	gomodule "golang.org/x/mod/module"

	"github.com/safedep/vet/v2/model"
)

// unitOf finds the source of a Go module or a Rust crate on the disk, in
// the vendor directory of the project first, then in the module or crate
// cache. vet never downloads a dependency.
func unitOf(dir string, id model.PackageVersion) (Unit, bool) {
	name, version := id.RawName(), strings.TrimSpace(id.RawVersion())
	switch id.Ecosystem() {
	case model.EcosystemGo:
		if name == "stdlib" {
			return stdlibUnit(strings.TrimPrefix(version, "v"))
		}
		v := "v" + strings.TrimPrefix(version, "v")
		key := "go:" + name + "@" + v
		escaped, err := gomodule.EscapePath(name)
		if err != nil {
			return Unit{}, false
		}
		escapedV, err := gomodule.EscapeVersion(v)
		if err != nil {
			return Unit{}, false
		}
		return firstDir(key, filepath.Join(dir, "vendor", filepath.FromSlash(name)), underHome(goModCache(), filepath.FromSlash(escaped)+"@"+escapedV))
	case model.EcosystemCargo:
		key := "cargo:" + name + "@" + version
		dirs := []string{filepath.Join(dir, "vendor", name+"-"+version), filepath.Join(dir, "vendor", name)}
		var registries []string
		if home := cargoHome(); home != "" {
			var err error
			registries, err = filepath.Glob(filepath.Join(home, "registry", "src", "*", name+"-"+version))
			if err != nil {
				// A crate name with a pattern character matches no registry.
				registries = nil
			}
		}
		return firstDir(key, append(dirs, registries...)...)
	}
	return Unit{}, false
}

// stdlibUnit reads the standard library of GOROOT only when it is the
// version of the project. A call path through another version proves
// nothing.
func stdlibUnit(version string) (Unit, bool) {
	root := cmp.Or(os.Getenv("GOROOT"), goEnvOf().GOROOT)
	if root == "" {
		return Unit{}, false
	}
	b, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		return Unit{}, false
	}
	first, _, _ := strings.Cut(string(b), "\n")
	if strings.TrimSpace(first) != "go"+version {
		return Unit{}, false
	}
	return firstDir("go:std@go"+version, filepath.Join(root, "src"))
}

// underHome joins a path to a cache root, or gives "" with no root.
func underHome(root, path string) string {
	if root == "" {
		return ""
	}
	return filepath.Join(root, path)
}

func firstDir(key string, dirs ...string) (Unit, bool) {
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			return Unit{Key: key, Dir: d}, true
		}
	}
	return Unit{}, false
}

// goEnv holds the paths that the go command reports.
type goEnv struct {
	GOMODCACHE string
	GOROOT     string
}

// goEnvOf asks the go command on the PATH once for each vet process, for
// the paths that its env file sets. An environment variable wins over it.
// With no go command, the defaults of the go command stand in.
var goEnvOf = sync.OnceValue(func() goEnv {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "env", "-json", "GOMODCACHE", "GOROOT")
	// The scan target can hold a go.mod with a toolchain line, and the go
	// command would download and run that toolchain. vet runs the command
	// outside the target, with the local toolchain only.
	cmd.Dir = os.TempDir()
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOFLAGS=")
	out, err := cmd.Output()
	if err != nil {
		log.Debugf("go env: %v", err)
		return goEnv{}
	}
	var env goEnv
	if err := json.Unmarshal(out, &env); err != nil {
		log.Debugf("go env: %v", err)
		return goEnv{}
	}
	return env
})

// goModCache is the module cache as the go command finds it: GOMODCACHE,
// else the first GOPATH entry, else $HOME/go. It gives "" with no home, so
// vet never reads a cache relative to the working directory.
func goModCache() string {
	if c := cmp.Or(os.Getenv("GOMODCACHE"), goEnvOf().GOMODCACHE); c != "" {
		return c
	}
	if p := filepath.SplitList(os.Getenv("GOPATH")); len(p) > 0 && p[0] != "" {
		return filepath.Join(p[0], "pkg", "mod")
	}
	return underHome(userHome(), filepath.Join("go", "pkg", "mod"))
}

// cargoHome is CARGO_HOME, else $HOME/.cargo, else "".
func cargoHome() string {
	if c := os.Getenv("CARGO_HOME"); c != "" {
		return c
	}
	return underHome(userHome(), ".cargo")
}

func userHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}
