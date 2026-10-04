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
	"github.com/safedep/dry/log"
)

// readManifests calls read with the content of each file under dir whose
// name match accepts, outside the directories of installed or built code.
// vet logs a file or a directory that it cannot read, and goes on.
func readManifests(dir string, match func(name string) bool, read func(path string, data []byte)) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Warnf("codeusage: skipped %s: %v", path, err)
			return nil
		}
		if d.IsDir() {
			if path != dir && skippedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !match(d.Name()) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			log.Warnf("codeusage: cannot read %s: %v", path, err)
			return nil
		}
		read(path, data)
		return nil
	})
}

// ownRoots returns the namespaces of the modules that the project itself
// declares, in the call graph form with "//": the Go module path, the Rust
// crate, the PHP namespace of the autoload map, the npm package and the
// Python distribution. A call into the project itself is not a capability
// of a dependency, so an SDK repository does not match its own signature.
// A file that vet cannot read or parse adds nothing, and vet logs it.
func ownRoots(dir string) ([]string, error) {
	var roots []string
	err := readManifests(dir, func(name string) bool { return ownReader(name) != nil }, func(path string, data []byte) {
		roots = append(roots, ownReader(filepath.Base(path))(path, data)...)
	})
	return roots, err
}

func ownReader(name string) func(path string, data []byte) []string {
	if strings.HasSuffix(name, ".gemspec") {
		return gemModules
	}
	return ownReaders[name]
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

func cargoCrate(path string, data []byte) []string {
	var c struct {
		Package struct {
			Name string `toml:"name"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(data), &c); err != nil {
		log.Warnf("codeusage: cannot parse %s: %v", path, err)
		return nil
	}
	if c.Package.Name == "" {
		return nil
	}
	return []string{strings.ReplaceAll(c.Package.Name, "-", "_")}
}

func composerNamespaces(path string, data []byte) []string {
	type autoload struct {
		PSR4 map[string]json.RawMessage `json:"psr-4"`
	}
	var c struct {
		Autoload    autoload `json:"autoload"`
		AutoloadDev autoload `json:"autoload-dev"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		log.Warnf("codeusage: cannot parse %s: %v", path, err)
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

func npmPackage(path string, data []byte) []string {
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		log.Warnf("codeusage: cannot parse %s: %v", path, err)
		return nil
	}
	if p.Name == "" {
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
		log.Warnf("codeusage: cannot parse %s: %v", path, err)
		return nil
	}
	var out []string
	for _, n := range []string{p.Project.Name, p.Tool.Poetry.Name} {
		if n != "" {
			// The module of a Python project is its name in lower case, with
			// "_" for each "-" and ".".
			out = append(out, strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToLower(n)))
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
