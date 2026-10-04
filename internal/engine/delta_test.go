package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

const baseLock = `{
  "name": "app", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "^1.2.0", "old": "1.0.0"}},
    "node_modules/left-pad": {"version": "1.2.0"},
    "node_modules/old": {"version": "1.0.0"}
  }
}`

const headLock = `{
  "name": "app", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "^1.3.0", "evil": "1.0.0"}},
    "node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/evil": {"version": "1.0.0"}
  }
}`

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
}

// gitProject commits the base files on main and then writes the head
// files to the working tree.
func gitProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)
	write(t, dir, "package-lock.json", baseLock)
	write(t, dir, "requirements.txt", "requests==2.31.0\n")
	write(t, dir, "legacy/requirements.txt", "six==1.16.0\n")
	wt, err := repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, wt.AddGlob("."))
	_, err = wt.Commit("base", &gogit.CommitOptions{Author: &object.Signature{Name: "t", Email: "t@example.com", When: time.Now()}})
	require.NoError(t, err)

	write(t, dir, "package-lock.json", headLock)
	write(t, dir, "tools/requirements.txt", "black==24.10.0\n")
	require.NoError(t, os.RemoveAll(filepath.Join(dir, "legacy")))
	return dir
}

func TestPullRequestMode(t *testing.T) {
	f := newFixture(t)
	en := &fakeEnricher{}
	o := f.options(t, gitProject(t), en,
		Control{ID: "evil", Plugin: nameControl{name: "evil"}},
		Control{ID: "requests", Plugin: nameControl{name: "requests"}},
	)
	o.BaseRef = "HEAD"
	res := runScan(t, o)
	ctx := context.Background()

	changes := map[string]model.Change{}
	previous := map[string]string{}
	for p, err := range res.Scan.Packages(ctx, plugin.PackageQuery{}) {
		require.NoError(t, err)
		changes[p.ID.String()] = p.Change
		previous[p.ID.String()] = p.PreviousVersion
	}
	assert.Equal(t, map[string]model.Change{
		"npm/left-pad@1.3.0":   model.ChangeUpgraded,
		"npm/evil@1.0.0":       model.ChangeAdded,
		"npm/old@1.0.0":        model.ChangeRemoved,
		"pypi/requests@2.31.0": model.ChangeUnchanged,
		"pypi/black@24.10.0":   model.ChangeAdded,
		"pypi/six@1.16.0":      model.ChangeRemoved,
	}, changes)
	assert.Equal(t, "1.2.0", previous["npm/left-pad@1.3.0"])

	kinds := map[string]model.Change{}
	for m, err := range res.Scan.Manifests(ctx) {
		require.NoError(t, err)
		kinds[m.Path] = m.Change
	}
	assert.Equal(t, map[string]model.Change{
		"package-lock.json":       model.ChangeModified,
		"requirements.txt":        model.ChangeUnchanged,
		"tools/requirements.txt":  model.ChangeAdded,
		"legacy/requirements.txt": model.ChangeRemoved,
	}, kinds)

	assert.Equal(t, 1, res.Entry.Findings, "the unchanged requests package gives no finding")
	assert.Equal(t, 3, en.seen, "only the introduced packages are enriched")
	assert.Equal(t, report.ScanModeDelta, res.Scan.Header().Scan.Mode)
}

func TestPullRequestModeNeedsGit(t *testing.T) {
	f := newFixture(t)
	o := f.options(t, project(t), nil)
	o.BaseRef = "main"
	res, err := Run(context.Background(), o)
	require.Error(t, err)
	assert.Equal(t, app.ExitUsage, app.ExitCode(err))
	assert.Nil(t, res, "a usage error is not a scan")
	es, err := o.Store.Index().List(context.Background(), state.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, es, "the index keeps no failed row for a usage error")
}

func TestDiff(t *testing.T) {
	id := func(name, v string) model.PackageVersion {
		return model.MustPackageVersion(model.EcosystemNpm, name, v)
	}
	head := &model.Manifest{Packages: []*model.Package{{ID: id("a", "1.0.0")}, {ID: id("b", "1.0.0")}}}
	base := &model.Manifest{Packages: []*model.Package{{ID: id("a", "1.0.0")}, {ID: id("b", "2.0.0")}}}
	diff(head, base, false)
	assert.Equal(t, model.ChangeUnchanged, head.Packages[0].Change)
	assert.Equal(t, model.ChangeDowngraded, head.Packages[1].Change)
	assert.Equal(t, model.ChangeModified, head.Change)

	same := &model.Manifest{Packages: []*model.Package{{ID: id("a", "1.0.0")}}}
	diff(same, &model.Manifest{Packages: []*model.Package{{ID: id("a", "1.0.0")}}}, true)
	assert.Equal(t, model.ChangeModified, same.Change, "a changed file is modified")

	diff(same, &model.Manifest{Packages: []*model.Package{{ID: id("a", "1.0.0")}}}, false)
	assert.Equal(t, model.ChangeUnchanged, same.Change)
}

func TestDiffRemovesOneOfTwoVersions(t *testing.T) {
	id := func(name, v string) model.PackageVersion {
		return model.MustPackageVersion(model.EcosystemNpm, name, v)
	}
	changes := func(m *model.Manifest) map[string]model.Change {
		out := map[string]model.Change{}
		for _, p := range m.Packages {
			out[p.ID.String()] = p.Change
		}
		return out
	}

	head := &model.Manifest{Packages: []*model.Package{{ID: id("foo", "2.0.0")}}}
	diff(head, &model.Manifest{Packages: []*model.Package{{ID: id("foo", "1.0.0")}, {ID: id("foo", "2.0.0")}}}, false)
	assert.Equal(t, map[string]model.Change{
		"npm/foo@2.0.0": model.ChangeUnchanged,
		"npm/foo@1.0.0": model.ChangeRemoved,
	}, changes(head))
	assert.Equal(t, model.ChangeModified, head.Change)

	upgraded := &model.Manifest{Packages: []*model.Package{{ID: id("foo", "3.0.0")}, {ID: id("foo", "2.0.0")}}}
	diff(upgraded, &model.Manifest{Packages: []*model.Package{{ID: id("foo", "1.0.0")}, {ID: id("foo", "2.0.0")}}}, false)
	assert.Equal(t, map[string]model.Change{
		"npm/foo@3.0.0": model.ChangeUpgraded,
		"npm/foo@2.0.0": model.ChangeUnchanged,
	}, changes(upgraded), "the version that an upgrade replaces is not also removed")
}

func TestPullRequestIntegrityAndPrior(t *testing.T) {
	lockOf := func(leftPad, msHash string) string {
		return `{"name": "app", "lockfileVersion": 3, "packages": {
  "": {"name": "app", "dependencies": {"left-pad": "^1.2.0", "ms": "2.1.3"}},
  "node_modules/left-pad": {"version": "` + leftPad + `", "integrity": "sha512-lp` + leftPad + `"},
  "node_modules/ms": {"version": "2.1.3", "integrity": "` + msHash + `"}
}}`
	}
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)
	write(t, dir, "package.json", `{"name": "app", "dependencies": {"left-pad": "^1.2.0", "ms": "2.1.3"}}`)
	write(t, dir, "package-lock.json", lockOf("1.2.0", "sha512-old"))
	wt, err := repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, wt.AddGlob("."))
	_, err = wt.Commit("base", &gogit.CommitOptions{Author: &object.Signature{Name: "t", Email: "t@example.com", When: time.Now()}})
	require.NoError(t, err)
	write(t, dir, "package-lock.json", lockOf("1.3.0", "sha512-new"))

	f := newFixture(t)
	en := &fakeEnricher{}
	o := f.options(t, dir, en)
	o.Enrichers[0].Prior = true
	o.BaseRef = "HEAD"
	res := runScan(t, o)
	ctx := context.Background()

	var lockID string
	for m, err := range res.Scan.Manifests(ctx) {
		require.NoError(t, err)
		if m.Path == "package-lock.json" {
			lockID = m.ID
			assert.True(t, m.LockfileOnly, "package.json did not change")
		}
	}
	require.NotEmpty(t, lockID)
	m, err := res.Scan.Manifest(ctx, lockID)
	require.NoError(t, err)
	byName := map[string]*model.Package{}
	for _, p := range m.Packages {
		byName[p.ID.RawName()] = p
	}
	assert.Equal(t, model.ChangeModified, byName["ms"].Change, "the same version with another hash")
	assert.Equal(t, "sha512-new", byName["ms"].Integrity)
	require.Equal(t, model.ChangeUpgraded, byName["left-pad"].Change)
	require.NotNil(t, byName["left-pad"].PreviousInsight, "the previous version gets its data")
	assert.Equal(t, []string{"MIT"}, byName["left-pad"].PreviousInsight.Licenses)
	assert.Equal(t, 3, en.seen, "left-pad, ms and the previous left-pad")
}

func changesOf(t *testing.T, res *Result) map[string]model.Change {
	t.Helper()
	out := map[string]model.Change{}
	for p, err := range res.Scan.Packages(context.Background(), plugin.PackageQuery{}) {
		require.NoError(t, err)
		out[p.ID.String()] = p.Change
	}
	return out
}

func TestPullRequestModeReusesBase(t *testing.T) {
	f := newFixture(t)
	dir := gitProject(t)
	o := f.options(t, dir, &fakeEnricher{})
	o.BaseRef = "HEAD"
	first := changesOf(t, runScan(t, o))

	bases, err := filepath.Glob(filepath.Join(f.store.StateDir(), baseDir, "*.json"))
	require.NoError(t, err)
	require.Len(t, bases, 1)

	second := changesOf(t, runScan(t, o))
	assert.Equal(t, first, second, "the kept base gives the same changes")

	require.NoError(t, os.WriteFile(bases[0], []byte(`{"version": 1, "manifests": [], "hashes": {}}`), 0o600))
	third := changesOf(t, runScan(t, o))
	for id, c := range third {
		assert.Equal(t, model.ChangeAdded, c, "%s: vet reads the kept base and does not extract again", id)
	}

	require.NoError(t, os.WriteFile(bases[0], []byte(`{"manifests": [], "hashes": {}}`), 0o600))
	assert.Equal(t, first, changesOf(t, runScan(t, o)), "a kept file of another version is extracted again")
}

func TestDiffMarksAChangedSourceModified(t *testing.T) {
	id := model.MustPackageVersion(model.EcosystemNpm, "ms", "2.1.3")
	npm := "https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz"
	evil := "https://evil.example/ms-2.1.3.tgz"
	cases := []struct {
		name       string
		base, head model.Package
		want       model.Change
	}{
		{"same entry", model.Package{Resolved: npm, Integrity: "sha512-a"}, model.Package{Resolved: npm, Integrity: "sha512-a"}, model.ChangeUnchanged},
		{"new URL", model.Package{Resolved: npm, Integrity: "sha512-a"}, model.Package{Resolved: evil, Integrity: "sha512-a"}, model.ChangeModified},
		{"new hash", model.Package{Integrity: "sha512-a"}, model.Package{Integrity: "sha512-b"}, model.ChangeModified},
		{"hash removed", model.Package{Resolved: npm, Integrity: "sha512-a"}, model.Package{Resolved: npm}, model.ChangeModified},
		{"hash added", model.Package{Resolved: npm}, model.Package{Resolved: npm, Integrity: "sha512-a"}, model.ChangeUnchanged},
		{"now local", model.Package{}, model.Package{Local: true}, model.ChangeModified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.base.ID, tc.head.ID = id, id
			head := &model.Manifest{Packages: []*model.Package{&tc.head}}
			diff(head, &model.Manifest{Packages: []*model.Package{&tc.base}}, true)
			assert.Equal(t, tc.want, tc.head.Change)
			assert.True(t, tc.head.Change.Introduces() == (tc.want == model.ChangeModified), "a modified entry gets the package findings in pull request mode")
			if tc.want == model.ChangeModified {
				assert.Equal(t, tc.base.Resolved, tc.head.PreviousResolved)
				assert.Equal(t, tc.base.Integrity, tc.head.PreviousIntegrity)
			}
		})
	}
}

func TestPreviousVersion(t *testing.T) {
	cases := []struct {
		name    string
		version string
		base    []string
		kept    []string
		want    string
	}{
		{"one base version", "2.0.0", []string{"1.0.0"}, nil, "1.0.0"},
		{"the closest below", "2.1.0", []string{"1.0.0", "2.0.0"}, []string{"1.0.0"}, "2.0.0"},
		{"base order does not matter", "2.1.0", []string{"2.0.0", "1.0.0"}, []string{"1.0.0"}, "2.0.0"},
		{"a downgrade takes the lowest above", "1.5.0", []string{"3.0.0", "2.0.0"}, nil, "2.0.0"},
		{"a kept version replaces nothing", "3.0.0", []string{"1.0.0", "2.0.0"}, []string{"1.0.0", "2.0.0"}, ""},
	}
	pv := func(v string) model.PackageVersion { return model.MustPackageVersion(model.EcosystemNpm, "x", v) }
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inHead := map[model.PackageKey]bool{pv(tc.version).Key(): true}
			for _, v := range tc.kept {
				inHead[pv(v).Key()] = true
			}
			var base []model.PackageVersion
			for _, v := range tc.base {
				base = append(base, pv(v))
			}
			got, ok := previousVersion(pv(tc.version), base, inHead)
			assert.Equal(t, tc.want != "", ok)
			if ok {
				assert.Equal(t, tc.want, got.RawVersion())
			}
		})
	}
}

func TestPullRequestModeReportsABaseThatVetCannotRead(t *testing.T) {
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)
	write(t, dir, "package-lock.json", `{"lockfileVersion": 3, "packages": {`)
	wt, err := repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, wt.AddGlob("."))
	_, err = wt.Commit("base", &gogit.CommitOptions{Author: &object.Signature{Name: "t", Email: "t@example.com", When: time.Now()}})
	require.NoError(t, err)
	write(t, dir, "package-lock.json", `{"name": "app", "lockfileVersion": 3, "packages": {
  "": {"name": "app", "dependencies": {"ms": "2.1.3"}},
  "node_modules/ms": {"version": "2.1.3", "integrity": "sha512-a"}
}}`)

	f := newFixture(t)
	o := f.options(t, dir, &fakeEnricher{})
	o.BaseRef = "HEAD"
	res := runScan(t, o)

	var messages []string
	for rec, err := range res.Scan.Records(context.Background()) {
		require.NoError(t, err)
		if rec.Diagnostic != nil {
			messages = append(messages, rec.Diagnostic.Message)
		}
	}
	assert.Contains(t, strings.Join(messages, "\n"), "read the base of package-lock.json")
	for id, c := range changesOf(t, res) {
		assert.Equal(t, model.ChangeAdded, c, "%s: a base that vet cannot read is empty", id)
	}
	bases, err := filepath.Glob(filepath.Join(f.store.StateDir(), baseDir, "*.json"))
	require.NoError(t, err)
	assert.Empty(t, bases, "vet does not keep a base with an error")
}
