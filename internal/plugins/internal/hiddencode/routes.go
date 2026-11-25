package hiddencode

import (
	"bytes"
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

// maxRouted is the most files that one analyzed file routes to. Each
// routed file costs a parse, and Analyze runs at the head and at the base.
const maxRouted = 16

// implicitHooks are the npm scripts that npm runs on its own around an
// install, a pack, a publish or a test. The user does not type their
// names, so the user does not see that they run.
var implicitHooks = []string{
	"preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare",
	"prepack", "postpack", "prepublish", "prepublishOnly", "postpublish", "pretest", "posttest",
}

// npmCommands are the npm commands that run the pre and post scripts of
// their name.
var npmCommands = map[string]bool{"install": true, "pack": true, "publish": true, "restart": true, "start": true, "stop": true, "test": true, "version": true}

// nodeRunners run the JavaScript file that an argument names.
var nodeRunners = map[string]bool{"node": true, "nodejs": true, "bun": true, "tsx": true, "ts-node": true, "babel-node": true}

// shells run the shell script that their first argument names.
var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true}

// wrappers run the command that follows them, after their own flags.
var wrappers = map[string]bool{"env": true, "cross-env": true, "exec": true, "command": true, "nohup": true, "time": true, "npx": true, "bunx": true, "yarn": true, "pnpm": true}

// scriptRunners run an npm script by its name with run or run-script.
var scriptRunners = map[string]bool{"npm": true, "pnpm": true, "yarn": true, "bun": true}

// preloadFlags load the module of their value before the script.
var preloadFlags = map[string]bool{"-r": true, "--require": true, "--import": true, "--loader": true, "--experimental-loader": true}

// setupKeys are the config keys of jest and vitest whose value names a
// file that the test runner loads.
var setupKeys = map[string]bool{
	"globalSetup": true, "globalTeardown": true, "setupFiles": true, "setupFilesAfterEnv": true,
	"testEnvironment": true, "testSequencer": true, "snapshotResolver": true,
}

// jsExts are the extensions that node tries for a path with none.
var jsExts = []string{".js", ".cjs", ".mjs", ".ts", ".cts", ".mts"}

var bom = []byte("\xef\xbb\xbf")

// implicit reports an npm script that npm runs on its own: a hook of
// implicitHooks, or the pre or post script of another script or of an npm
// command.
func implicit(name string, scripts map[string]string) bool {
	if slices.Contains(implicitHooks, name) {
		return true
	}
	for _, prefix := range []string{"pre", "post"} {
		if rest, ok := strings.CutPrefix(name, prefix); ok && rest != "" {
			if _, ok := scripts[rest]; ok || npmCommands[rest] {
				return true
			}
		}
	}
	return false
}

// router gives the dynamic-code check to the files that one analyzed file
// routes to, each file once, up to maxRouted files.
type router struct {
	fsys    fs.FS
	read    map[string]bool
	signals []Signal
}

func newRouter(fsys fs.FS) *router { return &router{fsys: fsys, read: map[string]bool{}} }

// route checks the file rel, which what names in the titles. vet does not
// follow the files that a routed file loads. A config of a tool often
// loads the library of the tool, and the false-positive run showed three
// warnings in the library of webpack with a second hop.
// known gap: a config that loads a clean helper, which loads the loader,
// gives no finding.
func (r *router) route(rel, what string) {
	if r.read[rel] || len(r.read) >= maxRouted {
		return
	}
	r.read[rel] = true
	if c, ok := Classify(rel); ok && (c == Config || c == Entry) {
		// A config or an npm entry script gets its own check.
		return
	}
	if ext := path.Ext(rel); ext != "" && !slices.Contains(jsExts, ext) {
		return
	}
	data, err := Open(r.fsys, rel, Config)
	if err != nil {
		// The route names the file, but the file is gone or vet cannot
		// read it. There is no code to report.
		return
	}
	for _, s := range dynamicCode(what, rel, data, true) {
		s.Path = rel
		r.signals = append(r.signals, s)
	}
}

// load routes to each file of the project that the file p loads.
func (r *router) load(p string, specs []string) {
	for _, spec := range specs {
		if !relative(spec) {
			continue
		}
		if rel, ok := localFile(r.fsys, path.Dir(p), spec); ok {
			r.route(rel, fmt.Sprintf("%s, which %s loads,", rel, path.Base(p)))
		}
	}
}

// relative reports a module path that names a file of the project. A bare
// name is a package.
func relative(spec string) bool {
	return strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../")
}

// rootDir turns the <rootDir> token of a jest path into a relative path.
// jest takes the folder of the config as the root when the config sets no
// other root.
func rootDir(spec string) string {
	if rest, ok := strings.CutPrefix(spec, "<rootDir>/"); ok {
		return "./" + rest
	}
	return spec
}

// loadedCode gives the dynamic-code check to each file of the project that
// a build config loads. A config that loads a file runs it at each build,
// test or lint, so a loader can sit there in place of the config.
func loadedCode(fsys fs.FS, p string, data []byte) []Signal {
	if !routable(fsys, p) {
		return nil
	}
	r := newRouter(fsys)
	r.load(p, loadedSpecs(p, data))
	return r.signals
}

// routable reports a file whose routes vet follows. An endpoint file has
// an absolute path, and its routes can name any file of the host, so vet
// follows none.
func routable(fsys fs.FS, p string) bool { return fsys != nil && !path.IsAbs(p) }

// pkgJSON is the part of a package.json that the route check reads.
type pkgJSON struct {
	scripts map[string]string
	// setup holds the paths of the setupKeys of the jest key.
	setup []string
}

// parsePkg reads a package.json as npm does. npm matches the keys with
// their case, so a "Scripts" key does not hide "scripts". A package.json
// that does not parse gives a diagnostic of the package.json extractor.
func parsePkg(data []byte) (pkgJSON, bool) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(bytes.TrimPrefix(data, bom), &raw) != nil {
		return pkgJSON{}, false
	}
	var pkg pkgJSON
	var scripts map[string]any
	if s, ok := raw["scripts"]; ok && json.Unmarshal(s, &scripts) == nil {
		pkg.scripts = map[string]string{}
		for name, v := range scripts {
			if cmd, ok := v.(string); ok {
				pkg.scripts[name] = cmd
			}
		}
	}
	var jest map[string]any
	if j, ok := raw["jest"]; ok && json.Unmarshal(j, &jest) == nil {
		for key, v := range jest {
			if setupKeys[key] {
				pkg.setup = append(pkg.setup, jsonStrings(v)...)
			}
		}
		slices.Sort(pkg.setup)
	}
	return pkg, true
}

// jsonStrings returns a JSON string, or the strings of a JSON array.
func jsonStrings(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// hookedCode reads the npm scripts and the jest key of a package.json.
// Each implicit script that runs a file of the project gives a
// script-hook-added signal. Each file that an implicit script or the test
// script runs, and each file that the jest key names, gets the
// dynamic-code check.
func hookedCode(fsys fs.FS, p string, data []byte) []Signal {
	if !routable(fsys, p) {
		return nil
	}
	pkg, ok := parsePkg(data)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(pkg.scripts))
	for name := range pkg.scripts {
		if name == "test" || implicit(name, pkg.scripts) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	dir := path.Dir(p)
	r := newRouter(fsys)
	var hooks []Signal
	for _, name := range names {
		cmd := pkg.scripts[name]
		hooked := map[string]bool{}
		for _, spec := range scriptFiles(cmd, pkg.scripts) {
			rel, ok := localFile(fsys, dir, spec)
			if !ok {
				continue
			}
			if implicit(name, pkg.scripts) && !hooked[rel] {
				hooked[rel] = true
				hooks = append(hooks, Signal{
					ID: IDScriptHook, Line: scriptLine(data, name), Visible: scriptSnippet(name, cmd),
					Title: fmt.Sprintf("The %s script runs %s, a file of the project. npm runs the script on its own, and the user does not see it", name, rel),
				})
			}
			r.route(rel, fmt.Sprintf("%s, which the %s script of %s runs,", rel, name, p))
		}
	}
	for _, spec := range pkg.setup {
		if spec = rootDir(spec); relative(spec) {
			if rel, ok := localFile(fsys, dir, spec); ok {
				r.route(rel, fmt.Sprintf("%s, which the jest key of %s loads,", rel, p))
			}
		}
	}
	return append(hooks, r.signals...)
}

// localFile resolves a path that a script or a module names, relative to
// the folder dir, to a regular file of fsys, as node does. It tries the
// path, then the path with each JavaScript extension, then its index.js.
// It rejects a path outside the target, a URL, a file of an install folder
// and a path through a symbolic link, which can point out of the target.
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
		if regular(fsys, c) {
			return c, true
		}
	}
	return "", false
}

// regular reports a regular file that no symbolic link leads to.
func regular(fsys fs.FS, rel string) bool {
	parts := strings.Split(rel, "/")
	for i := range parts {
		info, err := fs.Lstat(fsys, strings.Join(parts[:i+1], "/"))
		if err != nil || info.Mode()&fs.ModeSymlink != 0 {
			return false
		}
		if i == len(parts)-1 {
			return info.Mode().IsRegular()
		}
	}
	return false
}

// scriptFiles returns the files that an npm script runs with node, a node
// runner or a shell, and the modules that it preloads. The paths are
// relative to the folder of the package.json. It reads each command of a
// chain such as a && b; c, follows a cd, and follows npm run to one more
// script of scripts. It skips the variables that a command sets, and
// reads the preload flags of NODE_OPTIONS.
func scriptFiles(cmd string, scripts map[string]string) []string {
	return filesOf(cmd, scripts, 1)
}

func filesOf(cmd string, scripts map[string]string, depth int) []string {
	var out []string
	cd := "."
	for _, words := range commands(cmd) {
		at := func(spec string) string { return path.Join(cd, spec) }
		for len(words) > 0 {
			if name, value, ok := strings.Cut(words[0], "="); ok && !strings.HasPrefix(name, "-") {
				if name == "NODE_OPTIONS" {
					for _, spec := range nodeArgs(strings.Fields(value), true) {
						out = append(out, at(spec))
					}
				}
				words = words[1:]
				continue
			}
			if !wrappers[words[0]] || isScriptRun(words) {
				break
			}
			words = words[1:]
			for len(words) > 0 && strings.HasPrefix(words[0], "-") {
				words = words[1:]
			}
		}
		if len(words) == 0 {
			continue
		}
		name := path.Base(words[0])
		switch {
		case name == "cd":
			if len(words) != 2 || path.IsAbs(words[1]) {
				// vet cannot tell the folder of the commands that follow.
				return out
			}
			cd = path.Join(cd, words[1])
		case isScriptRun(words):
			if next, ok := scripts[words[2]]; ok && depth > 0 {
				out = append(out, filesOf(next, scripts, depth-1)...)
			} else if name == "bun" {
				for _, spec := range nodeArgs(words[2:], false) {
					out = append(out, at(spec))
				}
			}
		case shells[name] && len(words) > 2 && words[1] == "-c":
			for _, spec := range filesOf(words[2], scripts, depth) {
				out = append(out, at(spec))
			}
		case shells[name] && len(words) > 1 && !strings.HasPrefix(words[1], "-"):
			out = append(out, at(words[1]))
		case nodeRunners[name]:
			for _, spec := range nodeArgs(words[1:], false) {
				out = append(out, at(spec))
			}
		}
	}
	return out
}

// isScriptRun reports a command that runs an npm script by its name, such
// as npm run build.
func isScriptRun(words []string) bool {
	return len(words) > 2 && scriptRunners[path.Base(words[0])] && (words[1] == "run" || words[1] == "run-script")
}

// nodeArgs returns the paths in the arguments of node: the value of each
// preload flag, and each argument that is not a flag. A flag can take the
// next argument as its value, so the check keeps each word that is not a
// flag, and localFile keeps the words that name a file. A preload of a
// bare name loads a package, so it gives no path. With preloadOnly, it
// returns only the preloads, as for NODE_OPTIONS.
func nodeArgs(args []string, preloadOnly bool) []string {
	var out []string
	preload := func(spec string) {
		if relative(spec) {
			out = append(out, spec)
		}
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		flag, value, hasValue := strings.Cut(a, "=")
		switch {
		case preloadFlags[flag] && hasValue:
			preload(value)
		case preloadFlags[a] && i+1 < len(args):
			preload(args[i+1])
			i++
		case strings.HasPrefix(a, "-"), preloadOnly:
			// A flag, or a word of NODE_OPTIONS that loads nothing, names
			// no file.
		default:
			out = append(out, a)
		}
	}
	return out
}

// commands splits a shell command line into its commands, and each one
// into its words. A quote groups words. A newline, a parenthesis and the
// operators &&, ||, ;, | and & end a command.
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
		case strings.ContainsRune(";&|\n()", r):
			flushCmd()
		case r == ' ' || r == '\t' || r == '\r':
			flushWord()
		default:
			word.WriteRune(r)
			inWord = true
		}
	}
	flushCmd()
	return out
}

// scriptsKey finds the scripts key of a package.json.
var scriptsKey = regexp.MustCompile(`"scripts"\s*:\s*\{`)

// scriptLine returns the line of the key of an npm script in the scripts
// object of a package.json, or 1. A string with the same text before the
// scripts key can move the line.
func scriptLine(data []byte, name string) int {
	start := 0
	if loc := scriptsKey.FindIndex(data); loc != nil {
		start = loc[1]
	}
	key := []byte(`"` + name + `"`)
	for i := start; i < len(data); {
		j := bytes.Index(data[i:], key)
		if j < 0 {
			break
		}
		at := i + j
		rest := bytes.TrimLeft(data[at+len(key):], " \t\r\n")
		if len(rest) > 0 && rest[0] == ':' {
			return 1 + bytes.Count(data[:at], []byte("\n"))
		}
		i = at + len(key)
	}
	return 1
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
