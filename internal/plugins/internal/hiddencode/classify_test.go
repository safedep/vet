package hiddencode

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassify(t *testing.T) {
	cases := map[string]Class{
		"postcss.config.mjs":              Config,
		"client/tailwind.config.js":       Config,
		"next.config.ts":                  Config,
		"truffle.js":                      Config,
		"src/App.js":                      Config,
		".eslintrc.js":                    Config,
		"public/fonts/fa-solid-400.woff2": Asset,
		".vscode/spellright.dict":         Asset,
		"assets/logo.PNG":                 Asset,
		"temp_auto_push.bat":              Script,
		"scripts/release.sh":              Script,
		".gitignore":                      Script,
		"src/index.ts":                    Source,
		"lib/util.py":                     Source,
		"CLAUDE.md":                       Source,
		".cursor/rules/style.mdc":         Source,
	}
	for p, want := range cases {
		got, ok := Classify(p)
		assert.True(t, ok, p)
		assert.Equal(t, want, got, p)
	}
	for _, p := range []string{"README.md", "logo.svg", "package.json", "main.go"} {
		_, ok := Classify(p)
		assert.False(t, ok, p)
	}
}
