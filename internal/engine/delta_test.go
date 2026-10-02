package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
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
	if res != nil {
		require.NoError(t, res.Scan.Close())
	}
}

func TestDiff(t *testing.T) {
	id := func(name, v string) model.PackageID {
		return model.PackageID{Ecosystem: model.EcosystemNpm, Name: name, Version: v}
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

func TestSameBlobIgnoresCRLF(t *testing.T) {
	lf := []byte("on: push\njobs: {}\n")
	base := plumbing.ComputeHash(plumbing.BlobObject, lf)
	cases := []struct {
		name string
		data string
		want bool
	}{
		{name: "same bytes", data: string(lf), want: true},
		{name: "CRLF checkout of the LF blob", data: "on: push\r\njobs: {}\r\n", want: true},
		{name: "changed", data: "on: pull_request\njobs: {}\n"},
		{name: "changed with CRLF", data: "on: pull_request\r\njobs: {}\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sameBlob(fstest.MapFS{"ci.yml": {Data: []byte(tc.data)}}, "ci.yml", base)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
