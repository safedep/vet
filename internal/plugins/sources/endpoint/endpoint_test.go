package endpoint

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
	"github.com/safedep/vet/v2/internal/endpoint/inventory/scanners"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

func write(t *testing.T, path, data string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(data), 0o600))
}

// machineHome writes a home directory with one tool of each kind.
func machineHome(t *testing.T, skill string) string {
	t.Helper()
	home := t.TempDir()
	write(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers": {"db": {"command": "node", "args": ["db.js"], "env": {"DB_URL": "postgres://secret@host/db"}}}}`)
	write(t, filepath.Join(home, ".claude", "skills", skill, "SKILL.md"), "---\nname: "+skill+"\ndescription: A test skill.\n---\n")
	write(t, filepath.Join(home, ".vscode", "extensions", "extensions.json"), `[{"identifier": {"id": "ms-python.python"}, "version": "2023.20.0"}]`)
	write(t, filepath.Join(home, ".vscode", "tasks.json"), `{"version": "2.0.0", "tasks": []}`)
	write(t, filepath.Join(home, ".config", "Code", "User", "tasks.json"), `{"version": "2.0.0", "tasks": []}`)
	write(t, filepath.Join(home, ".npm-global", "lib", "node_modules", "left-pad", "package.json"), `{"name": "left-pad", "version": "1.3.0"}`)
	write(t, filepath.Join(home, ".npm-global", "lib", "node_modules", "@types", "node", "package.json"), `{"name": "@types/node", "version": "20.1.0"}`)
	return home
}

func fakeSystem(home string, others ...string) System {
	return System{
		Hostname:    func() (string, error) { return "Build-Host", nil },
		Home:        func() (string, error) { return home, nil },
		Homes:       func() ([]string, error) { return append([]string{home}, others...), nil },
		Privileged:  func() bool { return true },
		GlobalRoots: func() []string { return nil },
		Scanners: func() ([]inventory.Scanner, error) {
			return scanners.Build([]string{scanners.KindAITool, scanners.KindAgentSkill, scanners.KindIDEExtension})
		},
	}
}

func artifactOf(t *testing.T, s *Source) plugin.Artifact {
	t.Helper()
	as := plugintest.TestSource(t, s)
	require.Len(t, as, 1)
	return as[0]
}

func TestAuditOneUser(t *testing.T) {
	home := machineHome(t, "review")
	a := artifactOf(t, New(Options{}, fakeSystem(home)))

	assert.Equal(t, plugin.ArtifactEndpoint, a.Kind)
	assert.Equal(t, "endpoint:build-host", a.Key)

	kinds := map[report.InventoryKind][]string{}
	for _, it := range a.Inventory {
		kinds[it.Kind] = append(kinds[it.Kind], it.Name)
		assert.NotContains(t, it.Details["mcp.args"]+it.Details["mcp.command"], "secret", "a record holds no secret value")
	}
	assert.Contains(t, kinds[report.InventoryMCPServer], "db")
	assert.Contains(t, kinds[report.InventorySkill], "review")
	assert.Contains(t, kinds[report.InventoryEditorPlugin], "ms-python.python")

	var ids []string
	for _, m := range a.Manifests {
		assert.Equal(t, model.ManifestKindEndpoint, m.Kind)
		for _, p := range m.Packages {
			ids = append(ids, p.ID.PURL())
		}
	}
	assert.Contains(t, ids, "pkg:vscode/ms-python.python@2023.20.0")
	assert.Contains(t, ids, "pkg:npm/left-pad@1.3.0")
	assert.Contains(t, ids, "pkg:npm/%40types/node@20.1.0")

	rel := func(p string) string {
		r, err := filepath.Rel(a.Path, p)
		require.NoError(t, err)
		return filepath.ToSlash(r)
	}
	assert.Contains(t, a.Include, rel(filepath.Join(home, ".vscode", "tasks.json")))
	assert.Contains(t, a.Include, rel(filepath.Join(home, ".config", "Code", "User", "tasks.json")))
	assert.Contains(t, a.Include, rel(filepath.Join(home, ".cursor", "mcp.json")))
	for _, f := range a.Include {
		_, err := os.Stat(filepath.Join(a.Path, filepath.FromSlash(f)))
		assert.NoError(t, err, "the source includes files that exist only")
	}
}

func TestAuditAllUsers(t *testing.T) {
	alice, bob := machineHome(t, "alice-skill"), machineHome(t, "bob-skill")
	sys := fakeSystem(alice, bob)
	global := t.TempDir()
	write(t, filepath.Join(global, "npm", "package.json"), `{"name": "npm", "version": "10.0.0"}`)
	sys.GlobalRoots = func() []string { return []string{global} }

	a := artifactOf(t, New(Options{AllUsers: true}, sys))
	var skills []string
	for _, it := range a.Inventory {
		if it.Kind == report.InventorySkill {
			skills = append(skills, it.Name)
		}
	}
	assert.ElementsMatch(t, []string{"alice-skill", "bob-skill"}, skills)
	var roots []string
	for _, m := range a.Manifests {
		roots = append(roots, m.Path)
	}
	assert.Contains(t, roots, global, "--all-users reads the machine-wide global packages")

	sys.Privileged = func() bool { return false }
	for _, err := range New(Options{AllUsers: true}, sys).Artifacts(context.Background()) {
		assert.ErrorIs(t, err, ErrNeedsRoot)
	}
}

func TestOneUserReadsNoSystemRoot(t *testing.T) {
	sys := fakeSystem(machineHome(t, "s"))
	sys.GlobalRoots = func() []string {
		t.Error("an audit of one user reads no machine-wide directory")
		return nil
	}
	artifactOf(t, New(Options{}, sys))
}

func TestAuditProjects(t *testing.T) {
	home := machineHome(t, "review")
	code := filepath.Join(home, "code")
	for _, f := range []string{
		"api/next.config.mjs", "api/.vscode/tasks.json", "api/public/fonts/a.woff2", "api/.gitignore",
		"api/src/index.ts", "api/node_modules/x/postcss.config.js", "web/client/tailwind.config.js", "web/.git/hooks/pre-commit",
	} {
		write(t, filepath.Join(code, filepath.FromSlash(f)), "x")
	}
	a := artifactOf(t, New(Options{Projects: []string{code}}, fakeSystem(home)))
	var got []string
	prefix := under(t, a, code)
	for _, f := range a.Include {
		if rel, ok := strings.CutPrefix(f, prefix); ok {
			got = append(got, rel)
		}
	}
	assert.ElementsMatch(t, []string{
		"api/next.config.mjs", "api/.vscode/tasks.json", "api/public/fonts/a.woff2", "api/.gitignore", "web/client/tailwind.config.js",
	}, got, "the source files, node_modules and .git stay out")
}

func TestCheckProjects(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	write(t, file, "x")
	got, err := CheckProjects(dir, []string{dir})
	require.NoError(t, err)
	assert.Equal(t, []string{dir}, got)
	t.Chdir(dir)
	write(t, filepath.Join(dir, "code", "a"), "x")
	got, err = CheckProjects(dir, []string{"code"})
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(dir, "code")}, got, "a relative folder becomes absolute")
	_, err = CheckProjects(dir, []string{filepath.Join(dir, "missing")})
	assert.ErrorContains(t, err, "--projects")
	_, err = CheckProjects(dir, []string{file})
	assert.ErrorContains(t, err, "not a folder")
	if runtime.GOOS == "windows" {
		_, err = CheckProjects(`Z:\Users\x`, []string{dir})
		assert.ErrorContains(t, err, "not on volume")
	}
}

func TestAuditRelativeProjects(t *testing.T) {
	home := machineHome(t, "review")
	write(t, filepath.Join(home, "code", "api", "next.config.mjs"), "x")
	t.Chdir(home)
	a := artifactOf(t, New(Options{Projects: []string{"code"}}, fakeSystem(home)))
	assert.Contains(t, a.Include, filepath.ToSlash(filepath.Join(home, "code", "api", "next.config.mjs"))[1:])
}

func TestAuditNPMEntryScripts(t *testing.T) {
	home := machineHome(t, "review")
	cli := filepath.Join(home, ".npm-global", "lib", "node_modules", "npm", "lib", "cli.js")
	write(t, cli, "module.exports = require('./npm')\n")
	a := artifactOf(t, New(Options{}, fakeSystem(home)))
	rel, err := filepath.Rel(a.Path, cli)
	require.NoError(t, err)
	assert.Contains(t, a.Include, filepath.ToSlash(rel))
}

func TestAuditProjectsLinks(t *testing.T) {
	home := machineHome(t, "review")
	code := filepath.Join(home, "code")
	write(t, filepath.Join(code, "api", "cfg", "tasks.json"), "x")
	require.NoError(t, os.Symlink("cfg", filepath.Join(code, "api", ".vscode")))
	require.NoError(t, os.Symlink("..", filepath.Join(code, "api", "cfg", ".claude")))
	write(t, filepath.Join(code, "target", "next.config.mjs"), "x")
	require.NoError(t, os.MkdirAll(filepath.Join(code, "target", ".git"), 0o700))
	a := artifactOf(t, New(Options{Projects: []string{code}}, fakeSystem(home)))
	prefix := under(t, a, code)
	var got []string
	for _, f := range a.Include {
		if rel, ok := strings.CutPrefix(f, prefix); ok {
			got = append(got, rel)
		}
	}
	assert.ElementsMatch(t, []string{"api/.vscode/tasks.json", "target/next.config.mjs"}, got,
		"a linked config folder is read once, and a repository named target is not skipped")
}

func TestAuditProjectsReadsEachNameOfALinkedFolder(t *testing.T) {
	home := machineHome(t, "review")
	code := filepath.Join(home, "code")
	write(t, filepath.Join(code, "api", "cfg", "tasks.json"), "x")
	require.NoError(t, os.Symlink("cfg", filepath.Join(code, "api", ".claude")))
	require.NoError(t, os.Symlink("cfg", filepath.Join(code, "api", ".vscode")))
	a := artifactOf(t, New(Options{Projects: []string{code}}, fakeSystem(home)))
	assert.Contains(t, a.Include, under(t, a, code)+"api/.vscode/tasks.json", ".claude comes first and must not hide .vscode")
}

func TestAuditProjectsCapCountsLinkedFolders(t *testing.T) {
	old := maxProjectFiles
	maxProjectFiles = 2
	t.Cleanup(func() { maxProjectFiles = old })
	home := machineHome(t, "review")
	code := filepath.Join(home, "code")
	write(t, filepath.Join(code, "api", "cfg", "tasks.json"), "x")
	require.NoError(t, os.Symlink("cfg", filepath.Join(code, "api", ".claude")))
	require.NoError(t, os.Symlink("cfg", filepath.Join(code, "api", ".vscode")))
	write(t, filepath.Join(code, "api", "next.config.mjs"), "x")
	write(t, filepath.Join(code, "api", "vite.config.js"), "x")
	a := artifactOf(t, New(Options{Projects: []string{code}}, fakeSystem(home)))
	prefix := under(t, a, code)
	n := 0
	for _, f := range a.Include {
		if strings.HasPrefix(f, prefix) {
			n++
		}
	}
	assert.Equal(t, 2, n, "the cap holds across the linked folders that the walk follows")
}

// under returns the path of dir in a.Include, with a trailing slash. The
// audit names a file by its path from the root of its volume.
func under(t *testing.T, a plugin.Artifact, dir string) string {
	t.Helper()
	rel, err := filepath.Rel(a.Path, dir)
	require.NoError(t, err)
	return filepath.ToSlash(rel) + "/"
}
