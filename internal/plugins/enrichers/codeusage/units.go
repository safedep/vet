package codeusage

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
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
// cache. A vendor directory counts only when it holds the version of the
// lockfile, because the call paths of another version prove nothing. vet
// never downloads a dependency. The standard library of Go has no unit. A
// Python distribution is in the environment of the project, which
// pythonEnvironment reads.
func unitOf(dir string, id model.PackageVersion) (Unit, bool) {
	name, version := id.RawName(), strings.TrimSpace(id.RawVersion())
	switch {
	case id.GoStdlib():
		return Unit{}, false
	case id.Ecosystem() == model.EcosystemGo:
		v := "v" + strings.TrimPrefix(version, "v")
		// EscapePath and EscapeVersion reject a path or a version that could
		// leave the vendor directory or the module cache.
		escaped, err := gomodule.EscapePath(name)
		if err != nil {
			return Unit{}, false
		}
		escapedV, err := gomodule.EscapeVersion(v)
		if err != nil {
			return Unit{}, false
		}
		var vendor string
		if vendoredGo(dir)[name] == v {
			vendor = filepath.Join(dir, "vendor", filepath.FromSlash(name))
		}
		return firstDir("go:"+name+"@"+v, vendor, underHome(goModCache(), filepath.FromSlash(escaped)+"@"+escapedV))
	case id.Ecosystem() == model.EcosystemCargo:
		// A crate name or a version from the lockfile is one path element.
		// A name with a separator, a dot path or a pattern character could
		// read code from outside the vendor directory or the registry.
		if !pathElement(name) || !pathElement(version) {
			return Unit{}, false
		}
		dirs := []string{filepath.Join(dir, "vendor", name+"-"+version)}
		if vendoredCrate(filepath.Join(dir, "vendor", name)) == version {
			dirs = append(dirs, filepath.Join(dir, "vendor", name))
		}
		if home := cargoHome(); home != "" {
			registries, err := os.ReadDir(filepath.Join(home, "registry", "src"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				log.Debugf("cargo registry: %v", err)
			}
			for _, r := range registries {
				dirs = append(dirs, filepath.Join(home, "registry", "src", r.Name(), name+"-"+version))
			}
		}
		return firstDir("cargo:"+name+"@"+version, dirs...)
	}
	return Unit{}, false
}

func pathElement(s string) bool {
	return s != "" && s != "." && s != ".." && filepath.Base(s) == s && !strings.ContainsAny(s, `/\*?[]`)
}

// vendoredGo reads vendor/modules.txt, the list of the modules that go mod
// vendor copied, with the version of each. A missing file gives none.
func vendoredGo(dir string) map[string]string {
	b, err := os.ReadFile(filepath.Join(dir, "vendor", "modules.txt"))
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for line := range strings.Lines(string(b)) {
		// A module line is "# path version", or "# path version => replacement".
		// A replaced module holds other code, so it does not count.
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "#" {
			out[fields[1]] = fields[2]
		}
	}
	return out
}

// vendoredCrate reads the version of the package section of a vendored
// Cargo.toml, or "".
func vendoredCrate(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "Cargo.toml"))
	if err != nil {
		return ""
	}
	inPackage := false
	for line := range strings.Lines(string(b)) {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "["):
			inPackage = line == "[package]"
		case inPackage && strings.HasPrefix(line, "version"):
			if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "version" {
				return strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
	}
	return ""
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
}

// goEnvOf asks the go command on the PATH once for each vet process, for
// the paths that its env file sets. An environment variable wins over it.
// With no go command, the defaults of the go command stand in.
var goEnvOf = sync.OnceValue(func() goEnv {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "env", "-json", "GOMODCACHE")
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
