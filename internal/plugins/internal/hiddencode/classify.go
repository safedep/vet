// Package hiddencode finds code that a file of a repository hides: code
// after a run of spaces in a build config, a script in a file that claims
// to be a font, invisible Unicode characters that carry a payload, and a
// script that rewrites the git history. The hidden-code extractor and the
// hidden-code control share it, so the extractor adds a manifest only for
// a file that the control reports.
package hiddencode

import (
	"path"
	"regexp"
	"strings"

	"github.com/safedep/vet/v2/internal/plugins/internal/agentfiles"
)

// Class is the class of a file that can hide code.
type Class string

const (
	// Config is a build or tool config that runs when a developer builds,
	// tests or lints the project, such as postcss.config.mjs.
	Config Class = "config"
	// Asset is a font, an image or a dictionary file. It must hold no code.
	Asset Class = "asset"
	// Source is a source file or an agent instruction file, read for
	// invisible Unicode.
	Source Class = "source"
	// Script is a shell or batch script, or a .gitignore, read for a script
	// that rewrites the git history.
	Script Class = "script"
	// Entry is an entry script of a package manager in a global install,
	// such as npm/lib/cli.js. It runs at each npm or npx command. It is the
	// one class that sits in an install folder.
	Entry Class = "entry"
)

// entryFiles are the entry scripts of npm in its install folder.
var entryFiles = []string{"node_modules/npm/lib/cli.js", "node_modules/npm/bin/npm-cli.js", "node_modules/npm/bin/npx-cli.js"}

// EntryFiles returns the entry scripts of npm under a global package folder,
// such as /usr/local/lib/node_modules.
func EntryFiles(root string) []string {
	out := make([]string, 0, len(entryFiles))
	for _, f := range entryFiles {
		out = append(out, path.Join(root, strings.TrimPrefix(f, "node_modules/")))
	}
	return out
}

// configName matches the build and tool configs that load as code.
var configName = regexp.MustCompile(`(?i)^[\w.-]+\.(config|conf)(\.[\w-]+)?\.(js|mjs|cjs|ts|mts|cts)$|^\.?(eslintrc|babelrc|prettierrc|stylelintrc)\.(js|cjs|mjs)$|^(webpack|rollup|gatsby-(config|node|browser|ssr))(\.[\w-]+)?\.(js|mjs|cjs|ts)$|^(gulpfile|gruntfile)\.(js|mjs|cjs|ts)$`)

// configFiles are the other files that PolinRider changes and that load as
// code at each build or start.
var configFiles = map[string]bool{
	"truffle.js": true, "truffle-config.js": true, "tailwind.js": true, "App.js": true,
}

var assetExts = map[string]bool{
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".bmp": true, ".webp": true,
	".dict": true, ".llf": true,
}

var sourceExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".vue": true, ".svelte": true,
	".ts": true, ".mts": true, ".cts": true, ".tsx": true, ".py": true,
}

var scriptExts = map[string]bool{".bat": true, ".cmd": true, ".ps1": true, ".sh": true}

// generatedDirs hold built or vendored code. A minified bundle has long
// lines, runs of white space and odd characters, so vet checks it only for
// a payload in invisible characters. A GitHub Action and a VS Code
// extension run their built dist or out folder.
var generatedDirs = map[string]bool{"dist": true, "build": true, "vendor": true, "out": true, ".next": true, "coverage": true}

// generated reports a built, vendored or minified source file.
func generated(p string) bool {
	if strings.HasSuffix(path.Base(p), ".min.js") {
		return true
	}
	for _, part := range strings.Split(path.Dir(p), "/") {
		if generatedDirs[part] {
			return true
		}
	}
	return false
}

// Classify returns the class of a file by its slash path relative to the
// target. ok is false for a file that the controls do not read.
func Classify(p string) (c Class, ok bool) {
	base := path.Base(p)
	ext := strings.ToLower(path.Ext(base))
	for _, f := range entryFiles {
		if p == f || strings.HasSuffix(p, "/"+f) {
			return Entry, true
		}
	}
	switch {
	case configName.MatchString(base) || configFiles[base]:
		return Config, true
	case assetExts[ext]:
		return Asset, true
	case scriptExts[ext] || base == ".gitignore":
		return Script, true
	}
	if t, ok := agentfiles.Classify(p); ok && t == agentfiles.Instructions {
		return Source, true
	}
	if !sourceExts[ext] {
		return "", false
	}
	return Source, true
}

// MaxSize is the largest part of a file that the controls read. A config
// over the limit is a finding itself, because a real config is a few KiB.
// known gap: vet does not check the part of a source file after MaxSize.
const MaxSize = 4 << 20

// headSize is the part of an asset that the check reads.
const headSize = 512
