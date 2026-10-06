//go:build acceptance

package acceptance

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
	"github.com/stretchr/testify/require"
)

func TestAcceptance(t *testing.T) {
	binDir := buildVet(t)
	srcDir, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)

	cat, err := LoadCatalog("catalog.yaml")
	require.NoError(t, err)
	sel := selectorFromEnv()

	const root = "scripts"
	files, err := discoverScriptFiles(root)
	require.NoError(t, err)
	require.NotEmptyf(t, files, "no acceptance scripts found under %s", root)

	// testscript names each subtest by the base name of the script, so a
	// t.Run for each directory rebuilds the feature id in the test name.
	byDir := map[string][]string{}
	var dirs []string
	for _, f := range files {
		if !cat.Selects(f.id, sel) {
			continue
		}
		if _, seen := byDir[f.relDir]; !seen {
			dirs = append(dirs, f.relDir)
		}
		byDir[f.relDir] = append(byDir[f.relDir], f.path)
	}
	if len(byDir) == 0 {
		t.Skipf("no acceptance scripts match selector %+v", sel)
	}
	sort.Strings(dirs)

	for _, relDir := range dirs {
		category, _, _ := strings.Cut(relDir, "/")
		t.Run(relDir, func(t *testing.T) {
			testscript.Run(t, testscript.Params{
				Files: byDir[relDir],
				Setup: func(env *testscript.Env) error {
					env.Setenv("PATH", binDir+string(os.PathListSeparator)+env.Getenv("PATH"))
					if err := Sandbox(env); err != nil {
						return err
					}
					// A script reads files of the source tree, such as the
					// scripts of the GitHub Action, from VET_SRC.
					env.Setenv("VET_SRC", srcDir)
					if category == "live" {
						// A live script calls production, so it gets the host
						// credentials and no stub.
						ForwardEnv(env, "SAFEDEP_API_KEY", "SAFEDEP_TENANT_ID")
						return nil
					}
					return StartStub(env, "stub/fixtures")
				},
				Cmds:      Commands(),
				Condition: Condition,
			})
		})
	}
}

// buildVet builds the binary once, or uses VET_BIN, and returns its
// directory for PATH.
func buildVet(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("VET_BIN")
	if bin == "" {
		name := "vet"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		bin = filepath.Join(t.TempDir(), name)
		build := exec.Command("go", "build", "-ldflags", "-X github.com/safedep/vet/v2/internal/version.version="+HarnessVersion, "-o", bin, "../../cmd/vet")
		build.Stderr = os.Stderr
		require.NoError(t, build.Run(), "build vet for the acceptance run")
	}
	// testscript resolves exec targets through PATH from the script
	// directory, so the path must be absolute.
	bin, err := filepath.Abs(bin)
	require.NoError(t, err)
	vetBinary = bin
	return filepath.Dir(bin)
}

type scriptFile struct {
	path   string
	relDir string
	id     string
}

func discoverScriptFiles(root string) ([]scriptFile, error) {
	var out []scriptFile
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".txtar" {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out = append(out, scriptFile{path: path, relDir: filepath.ToSlash(filepath.Dir(rel)), id: DeriveFeatureID(rel)})
		return nil
	})
	return out, err
}

// selectorFromEnv reads the optional category and label filters. The
// workflow passes them as variables, never as shell arguments.
func selectorFromEnv() Selector {
	sel := Selector{Category: strings.TrimSpace(os.Getenv("ACCEPTANCE_CATEGORY"))}
	for _, l := range strings.Split(os.Getenv("ACCEPTANCE_LABELS"), ",") {
		if l = strings.TrimSpace(l); l != "" {
			sel.Labels = append(sel.Labels, l)
		}
	}
	return sel
}
