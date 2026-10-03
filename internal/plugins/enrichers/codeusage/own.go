package codeusage

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// ownRoots returns the namespaces of the modules that the project itself
// declares, in the call graph form with "//": the Go module path, the Rust
// crate, the PHP namespace of the autoload map, the npm package and the
// Python distribution. A call into the project itself is not a capability
// of a dependency, so an SDK repository does not match its own signature.
// A file that vet cannot read or parse adds nothing.
func ownRoots(dir string) ([]string, error) {
	var roots []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != dir && skippedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		read := ownReaders[d.Name()]
		if strings.HasSuffix(d.Name(), ".gemspec") {
			read = gemModules
		}
		if read == nil {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		roots = append(roots, read(path, data)...)
		return nil
	})
	return roots, err
}

// ownReaders read the own namespaces from a manifest, by file name.
var ownReaders = map[string]func(path string, data []byte) []string{
	"go.mod":         goModule,
	"Cargo.toml":     cargoCrate,
	"composer.json":  composerNamespaces,
	"package.json":   npmPackage,
	"pyproject.toml": pythonDistribution,
}

func goModule(_ string, data []byte) []string {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if mod, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "module "); ok {
			return []string{slashRoot(strings.Trim(strings.TrimSpace(mod), `"`))}
		}
	}
	return nil
}

func cargoCrate(_ string, data []byte) []string {
	var c struct {
		Package struct {
			Name string `toml:"name"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(data), &c); err != nil || c.Package.Name == "" {
		return nil
	}
	return []string{strings.ReplaceAll(c.Package.Name, "-", "_")}
}

func composerNamespaces(_ string, data []byte) []string {
	type autoload struct {
		PSR4 map[string]json.RawMessage `json:"psr-4"`
	}
	var c struct {
		Autoload    autoload `json:"autoload"`
		AutoloadDev autoload `json:"autoload-dev"`
	}
	if json.Unmarshal(data, &c) != nil {
		return nil
	}
	var out []string
	for _, a := range []autoload{c.Autoload, c.AutoloadDev} {
		for prefix := range a.PSR4 {
			if ns := strings.Trim(prefix, `\`); ns != "" {
				out = append(out, strings.ReplaceAll(ns, `\`, "//"))
			}
		}
	}
	return out
}

func npmPackage(_ string, data []byte) []string {
	var p struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(data, &p) != nil || p.Name == "" {
		return nil
	}
	return []string{slashRoot(p.Name)}
}

// pythonDistribution returns the import names of the project: the name of
// the distribution with "_" for "-", as crewai for crewai, and each package
// directory next to the pyproject.toml or under its src directory, as agents
// for the openai-agents distribution.
func pythonDistribution(path string, data []byte) []string {
	var p struct {
		Project struct {
			Name string `toml:"name"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Name string `toml:"name"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if _, err := toml.Decode(string(data), &p); err != nil {
		return nil
	}
	var out []string
	for _, n := range []string{p.Project.Name, p.Tool.Poetry.Name} {
		if n != "" {
			out = append(out, strings.ReplaceAll(strings.ToLower(pep503(n)), "-", "_"))
		}
	}
	dir := filepath.Dir(path)
	for _, parent := range []string{dir, filepath.Join(dir, "src")} {
		entries, err := os.ReadDir(parent)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() && fileExists(filepath.Join(parent, e.Name(), "__init__.py")) {
				out = append(out, e.Name())
			}
		}
	}
	return out
}

// gemModules returns the top module or class of each file under the lib
// directory of a gem, as OpenAI for lib/openai.rb of ruby-openai. A Ruby
// constant does not name its gem, so the file content tells.
func gemModules(path string, _ []byte) []string {
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "lib", "*.rb"))
	if err != nil {
		return nil
	}
	var out []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if m := rubyTopConstant.FindSubmatch(data); m != nil {
			out = append(out, string(m[1]))
		}
	}
	return out
}

var rubyTopConstant = regexp.MustCompile(`(?m)^(?:module|class)\s+([A-Z]\w*)`)

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func slashRoot(name string) string { return strings.ReplaceAll(name, "/", "//") }

// inRoots reports whether a callee is in one of the namespaces.
func inRoots(callee string, roots []string) bool {
	for _, r := range roots {
		if callee == r || strings.HasPrefix(callee, r+"//") {
			return true
		}
	}
	return false
}
