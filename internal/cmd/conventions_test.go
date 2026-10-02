package cmd

import (
	"bytes"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
)

// The conventions of docs/DEVGUIDE.md, sections "Command shape" and
// "Documentation". The lists below change only with the program owner.
var (
	// rootLevelExceptions are the leaves at depth 1.
	rootLevelExceptions = []string{"doctor", "scan", "version"}
	// hyphenExceptions are the command names that can have a hyphen.
	hyphenExceptions = []string{"github-actions"}
	// topLevelCommands are the children of the root in v2.0. "endpoint"
	// lands with vet endpoint audit in v2.x.
	topLevelCommands = []string{"auth", "config", "doctor", "fix", "policy", "report", "scan", "state", "version"}
	// leafCommands are the leaves of the tree of the command layout,
	// section 3.2, in v2.0.
	leafCommands = []string{
		"scan",
		"report show", "report list", "report diff", "report finding show", "report schema get",
		"policy init", "policy validate", "policy control list", "policy schema get",
		"fix github-actions run",
		"state show", "state delete",
		"doctor",
		"config show", "config get", "config set", "config delete", "config edit", "config validate",
		"config schema get",
		"auth login", "auth status", "auth logout",
		"version",
	}
)

const maxDepth = 3

const module = "github.com/safedep/vet/v2"

func newTree(t *testing.T) *cobra.Command {
	t.Helper()
	return New(app.New(app.Options{}))
}

func isCobraGenerated(c *cobra.Command) bool {
	return c.Name() == "help" || c.Name() == "completion"
}

func isLeaf(c *cobra.Command) bool { return c.Run != nil || c.RunE != nil }

// walk calls fn for each command under the root with its path, the root
// excluded.
func walk(c *cobra.Command, path []string, fn func(c *cobra.Command, path []string)) {
	for _, child := range c.Commands() {
		if isCobraGenerated(child) {
			continue
		}
		p := append(slices.Clone(path), child.Name())
		fn(child, p)
		walk(child, p, fn)
	}
}

func leaves(t *testing.T) map[string]*cobra.Command {
	t.Helper()
	out := map[string]*cobra.Command{}
	walk(newTree(t), nil, func(c *cobra.Command, path []string) {
		if isLeaf(c) {
			out[strings.Join(path, " ")] = c
		}
	})
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Join(wd, "..", "..")
}

func docPage(t *testing.T, path string) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "docs", "cmd", strings.ReplaceAll(path, " ", "-")+".md")
}

func TestConventions_LeafShape(t *testing.T) {
	for path, c := range leaves(t) {
		parts := strings.Fields(path)
		if len(parts) == 1 {
			assert.Contains(t, rootLevelExceptions, path, "leaf %q at depth 1 is not a root exception", path)
			continue
		}
		assert.True(t, IsAllowedVerb(c.Name()), "leaf %q ends in %q, which is not in verbs.go", path, c.Name())
	}
}

func TestConventions_NoHyphensInUse(t *testing.T) {
	walk(newTree(t), nil, func(c *cobra.Command, path []string) {
		if strings.Contains(c.Name(), "-") {
			assert.Contains(t, hyphenExceptions, c.Name(), "command %q has a hyphen", strings.Join(path, " "))
		}
	})
}

func TestConventions_ShortAndLongPresent(t *testing.T) {
	root := newTree(t)
	assert.NotEmpty(t, root.Short, "the root has no Short")
	assert.NotEmpty(t, root.Long, "the root has no Long")
	walk(root, nil, func(c *cobra.Command, path []string) {
		assert.NotEmpty(t, c.Short, "%q has no Short", strings.Join(path, " "))
		assert.NotEmpty(t, c.Long, "%q has no Long", strings.Join(path, " "))
	})
}

func TestConventions_TopLevelCommands(t *testing.T) {
	var names []string
	for _, c := range newTree(t).Commands() {
		if !isCobraGenerated(c) {
			names = append(names, c.Name())
		}
	}
	assert.ElementsMatch(t, topLevelCommands, names,
		"top-level commands changed. Update topLevelCommands and docs/DEVGUIDE.md")
}

func TestConventions_Leaves(t *testing.T) {
	assert.ElementsMatch(t, leafCommands, slices.Collect(maps.Keys(leaves(t))),
		"leaves changed. Update leafCommands and docs/DEVGUIDE.md")
}

func TestConventions_MaxDepth(t *testing.T) {
	for path := range leaves(t) {
		assert.LessOrEqual(t, len(strings.Fields(path)), maxDepth, "leaf %q is deeper than %d", path, maxDepth)
	}
}

func TestConventions_PersistentFlagsOnRootOnly(t *testing.T) {
	walk(newTree(t), nil, func(c *cobra.Command, path []string) {
		c.PersistentFlags().VisitAll(func(f *pflag.Flag) {
			assert.Fail(t, "persistent flag below the root", "%q declares --%s", strings.Join(path, " "), f.Name)
		})
	})
}

func TestConventions_LeafDocPagesExist(t *testing.T) {
	for path := range leaves(t) {
		assert.FileExists(t, docPage(t, path), "leaf %q has no page", path)
	}
}

func TestConventions_NoOrphanDocPages(t *testing.T) {
	want := map[string]bool{}
	for path := range leaves(t) {
		want[filepath.Base(docPage(t, path))] = true
	}
	pages, err := filepath.Glob(filepath.Join(repoRoot(t), "docs", "cmd", "*.md"))
	require.NoError(t, err)
	for _, p := range pages {
		assert.True(t, want[filepath.Base(p)], "page %s has no leaf command", filepath.Base(p))
	}
}

func TestConventions_DocPageSections(t *testing.T) {
	for path := range leaves(t) {
		b, err := os.ReadFile(docPage(t, path))
		if err != nil {
			continue
		}
		page := string(b)
		assert.True(t, strings.HasPrefix(page, "# vet "+path+"\n"), "page of %q must start with \"# vet %s\"", path, path)
		for _, section := range []string{"## Synopsis", "## Exit codes"} {
			assert.Contains(t, page, "\n"+section+"\n", "page of %q has no %q section", path, section)
		}
	}
}

func TestConventions_DocPageNamesEveryFlag(t *testing.T) {
	for path, c := range leaves(t) {
		b, err := os.ReadFile(docPage(t, path))
		if err != nil {
			continue
		}
		c.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
			assert.Contains(t, string(b), "--"+f.Name, "page of %q does not name --%s", path, f.Name)
		})
	}
}

func TestConventions_ReadmeLinksAllDocPages(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join(repoRoot(t), "README.md"))
	require.NoError(t, err)
	pages, err := filepath.Glob(filepath.Join(repoRoot(t), "docs", "cmd", "*.md"))
	require.NoError(t, err)
	for _, p := range pages {
		link := "docs/cmd/" + filepath.Base(p)
		assert.Contains(t, string(readme), "("+link+")", "README.md does not link %s", link)
	}
}

func TestConventions_NoCrossCmdImports(t *testing.T) {
	cmd := exec.Command("go", "list", "-f", `{{.ImportPath}}|{{join .Imports ","}}`, module+"/internal/cmd/...")
	cmd.Dir = repoRoot(t)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, stderr.String())

	base := module + "/internal/cmd/"
	noun := func(path string) string {
		if !strings.HasPrefix(path, base) {
			return ""
		}
		return strings.SplitN(strings.TrimPrefix(path, base), "/", 2)[0]
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(line, "|", 2)
		from := noun(parts[0])
		if from == "" || len(parts) < 2 || parts[1] == "" {
			continue
		}
		for _, imp := range strings.Split(parts[1], ",") {
			if to := noun(imp); to != "" && to != from {
				assert.Fail(t, "command packages import each other", "%s imports %s", parts[0], imp)
			}
		}
	}
}
