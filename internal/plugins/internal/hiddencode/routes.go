package hiddencode

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
)

// The subjects of the dynamic-code titles of the files that vet analyzes
// itself.
const (
	configText = "The build config"
	entryText  = "The npm entry script"
)

// implicitHooks are the npm scripts that npm runs on its own, around an
// install, a pack, a publish or a test. A developer who runs npm install
// or npm test runs them with no sign.
var implicitHooks = []string{
	"preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare",
	"prepack", "postpack", "prepublish", "prepublishOnly", "pretest", "posttest",
}

// routedScript reports an npm script whose files vet reads for dynamic
// code: an implicit hook, or test, which each CI runs.
func routedScript(name string) bool { return name == "test" || slices.Contains(implicitHooks, name) }

// nodeRunners run the JavaScript file that their first argument names.
var nodeRunners = map[string]bool{"node": true, "nodejs": true, "bun": true, "tsx": true, "ts-node": true, "babel-node": true}

// preloadFlags load the module of their next argument before the script.
var preloadFlags = map[string]bool{"-r": true, "--require": true, "--import": true, "--loader": true, "--experimental-loader": true}

// jsExts are the extensions that node tries for a path with none.
var jsExts = []string{".js", ".cjs", ".mjs", ".ts", ".cts", ".mts"}

// hookedCode reads the npm scripts of a package.json. Each implicit hook
// that runs a file of the project gives a script-hook-added signal, and
// each file that a routed script runs gets the dynamic-code check.
func hookedCode(fsys fs.FS, p string, data []byte) []Signal {
	if fsys == nil {
		return nil
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	// A package.json that does not parse gives a diagnostic of the
	// package.json extractor, so the check reads nothing.
	if json.Unmarshal(data, &pkg) != nil {
		return nil
	}
	names := make([]string, 0, len(pkg.Scripts))
	for name := range pkg.Scripts {
		if routedScript(name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	var out []Signal
	read := map[string]bool{}
	for _, name := range names {
		cmd := pkg.Scripts[name]
		for _, spec := range scriptFiles(cmd) {
			rel, ok := localFile(fsys, path.Dir(p), spec)
			if !ok {
				continue
			}
			if slices.Contains(implicitHooks, name) {
				out = append(out, Signal{
					ID: IDScriptHook, Line: scriptLine(data, name), Visible: scriptSnippet(name, cmd),
					Title: fmt.Sprintf("The %s script runs %s, a file of the project. npm runs it with no sign", name, rel),
				})
			}
			if !read[rel] {
				read[rel] = true
				out = append(out, routedCode(fsys, rel, fmt.Sprintf("%s, which the %s script of %s runs,", rel, name, p))...)
			}
		}
	}
	return out
}

// loadedCode gives the dynamic-code check to each file of the project that
// a build config loads. A config that loads a file runs it at each build,
// test or lint, so a loader can sit there in place of the config.
func loadedCode(fsys fs.FS, p string, data []byte) []Signal {
	if fsys == nil {
		return nil
	}
	var out []Signal
	read := map[string]bool{}
	for _, spec := range loadedSpecs(p, data) {
		if !strings.HasPrefix(spec, "./") && !strings.HasPrefix(spec, "../") {
			continue
		}
		rel, ok := localFile(fsys, path.Dir(p), spec)
		if !ok || read[rel] {
			continue
		}
		read[rel] = true
		out = append(out, routedCode(fsys, rel, fmt.Sprintf("%s, which %s loads,", rel, path.Base(p)))...)
	}
	return out
}

// routedCode runs the dynamic-code check on a file that a config loads or
// that an npm script runs. A config or an npm entry script gets its own
// check, so it gets none here.
func routedCode(fsys fs.FS, rel, what string) []Signal {
	if c, ok := Classify(rel); ok && (c == Config || c == Entry) {
		return nil
	}
	data, err := Open(fsys, rel, Config)
	if err != nil {
		// The file of a route is gone or unreadable. The route itself
		// names it, so there is nothing to report.
		return nil
	}
	signals := dynamicCode(what, rel, data, true)
	for i := range signals {
		signals[i].Path = rel
	}
	return signals
}

// localFile resolves a path that a script or a module names, relative to
// the folder dir, to a regular file of fsys, as node does: the path, then
// the path with each JavaScript extension, then its index.js. It rejects a
// path outside the target, a URL and a file of an install folder.
func localFile(fsys fs.FS, dir, spec string) (string, bool) {
	if spec == "" || path.IsAbs(spec) || strings.Contains(spec, "://") || strings.HasPrefix(spec, "-") {
		return "", false
	}
	clean := path.Clean(path.Join(dir, spec))
	if clean == ".." || strings.HasPrefix(clean, "../") || slices.Contains(strings.Split(clean, "/"), "node_modules") {
		return "", false
	}
	candidates := []string{clean}
	for _, ext := range jsExts {
		candidates = append(candidates, clean+ext)
	}
	candidates = append(candidates, clean+"/index.js")
	for _, c := range candidates {
		if info, err := fs.Stat(fsys, c); err == nil && info.Mode().IsRegular() {
			return c, true
		}
	}
	return "", false
}

// scriptFiles returns the files that an npm script runs with node or a
// node runner, and the modules that it preloads. It reads each command of
// a chain such as a && b; c, and skips the variables that a command sets.
func scriptFiles(cmd string) []string {
	var out []string
	for _, words := range commands(cmd) {
		for len(words) > 0 && (strings.Contains(words[0], "=") || words[0] == "env" || words[0] == "cross-env" || words[0] == "npx") {
			words = words[1:]
		}
		if len(words) == 0 || !nodeRunners[path.Base(words[0])] {
			continue
		}
		args := words[1:]
		if len(args) > 0 && args[0] == "run" && words[0] == "bun" {
			args = args[1:]
		}
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case preloadFlags[a] && i+1 < len(args):
				out = append(out, args[i+1])
				i++
			case strings.HasPrefix(a, "-"):
				// A flag of node, such as --max-old-space-size=4096.
			default:
				out = append(out, a)
				i = len(args)
			}
		}
	}
	return out
}

// commands splits a shell command line into its commands, and each one
// into its words. A quote groups words, and the operators &&, ||, ;, |
// and & end a command.
func commands(line string) [][]string {
	var out [][]string
	var words []string
	var word strings.Builder
	inWord := false
	flushWord := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
	}
	flushCmd := func() {
		flushWord()
		if len(words) > 0 {
			out = append(out, words)
			words = nil
		}
	}
	var quote rune
	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == ';' || r == '&' || r == '|':
			flushCmd()
		case r == ' ' || r == '\t' || r == '\n':
			flushWord()
		default:
			word.WriteRune(r)
			inWord = true
		}
	}
	flushCmd()
	return out
}

// scriptLine returns the line of the key of an npm script in a
// package.json, or 1.
func scriptLine(data []byte, name string) int {
	start := 0
	if i := strings.Index(string(data), `"scripts"`); i >= 0 {
		start = i
	}
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(name) + `"\s*:`)
	loc := re.FindIndex(data[start:])
	if loc == nil {
		return 1
	}
	return 1 + strings.Count(string(data[:start+loc[0]]), "\n")
}

// maxSnippet is the longest command that a finding shows.
const maxSnippet = 120

// scriptSnippet shows an npm script as its package.json line.
func scriptSnippet(name, cmd string) string {
	if r := []rune(cmd); len(r) > maxSnippet {
		cmd = string(r[:maxSnippet]) + "..."
	}
	return fmt.Sprintf("%q: %q", name, cmd)
}
