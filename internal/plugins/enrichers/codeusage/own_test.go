package codeusage

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/gitbase/gitbasetest"
)

func TestOwnReaders(t *testing.T) {
	cases := []struct {
		file string
		data string
		want []string
	}{
		{"go.mod", "module github.com/tmc/langchaingo\n\ngo 1.22\n", []string{"github.com//tmc//langchaingo"}},
		{"Cargo.toml", "[package]\nname = \"async-openai\"\nversion = \"0.1.0\"\n", []string{"async_openai"}},
		{"Cargo.toml", "[workspace]\nmembers = [\"a\"]\n", nil},
		{"composer.json", `{"autoload":{"psr-4":{"OpenAI\\":"src/"},"files":["src/OpenAI.php"]},"autoload-dev":{"psr-4":{"Tests\\Unit\\":"tests/"}}}`, []string{"OpenAI", "Tests//Unit"}},
		{"package.json", `{"name":"@anthropic-ai/sdk"}`, []string{"@anthropic-ai//sdk"}},
		{"pyproject.toml", "[project]\nname = \"Crew-AI.Tools\"\n", []string{"crew_ai_tools"}},
		{"pyproject.toml", "[tool.poetry]\nname = \"my-agent\"\n", []string{"my_agent"}},
		{"package.json", "{", nil},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			assert.ElementsMatch(t, c.want, ownReaders[c.file](filepath.Join(t.TempDir(), c.file), []byte(c.data)))
		})
	}
}

func TestOwnPackageDirectories(t *testing.T) {
	dir := t.TempDir()
	gitbasetest.Write(t, dir, "pyproject.toml", "[project]\nname = \"openai-agents\"\n")
	gitbasetest.Write(t, dir, "src/agents/__init__.py", "")
	gitbasetest.Write(t, dir, "docs/conf.py", "")
	gitbasetest.Write(t, dir, "ruby-openai.gemspec", "Gem::Specification.new")
	gitbasetest.Write(t, dir, "lib/openai.rb", "require 'faraday'\n\nmodule OpenAI\n  class Error < StandardError; end\nend\n")
	gitbasetest.Write(t, dir, "node_modules/x/package.json", `{"name":"skipped"}`)
	roots, err := ownRoots(dir)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"openai_agents", "agents", "OpenAI"}, roots)
}

func TestOwnCallsAreNotCapabilities(t *testing.T) {
	dir := t.TempDir()
	gitbasetest.Write(t, dir, "go.mod", "module github.com/acme/sdk\n")
	gitbasetest.Write(t, dir, "vendor/x/go.mod", "module github.com/vendored/x\n")
	match := func(id, callee string) Match {
		return Match{Signature: Signature{ID: id}, FilePath: "main.go", Line: 1, Callee: callee}
	}
	analyzer := func(context.Context, string) (Analysis, error) {
		return Analysis{Matches: []Match{
			match("acme.client", "github.com//acme//sdk//NewClient"),
			match("acme.client", "github.com//acme//sdk"),
			match("openai.client", "github.com//openai//openai-go//NewClient"),
			match("other.client", "github.com//acme//sdk-extra//New"),
			match("vendored.client", "github.com//vendored//x//New"),
		}}, nil
	}
	caps, err := NewWith(dir, Options{}, analyzer).Capabilities(context.Background())
	require.NoError(t, err)
	var got []string
	for _, c := range caps {
		got = append(got, c.ID)
	}
	assert.Equal(t, []string{"openai.client", "other.client", "vendored.client"}, got, "a call into the module itself is not a capability")
}
