package nvimplugin

import (
	"context"
	"path/filepath"
	"testing"
)

// lazyFixture builds a temp Neovim tree and returns the Env pointing at it.
// installed maps plugin dir name -> origin URL (a clone with HEAD=testSHA
// is written for each). lock is written verbatim as lazy-lock.json when
// non-empty.
func lazyFixture(t *testing.T, installed map[string]string, lock string) Env {
	t.Helper()
	home := t.TempDir()
	configDir := filepath.Join(home, ".config", "nvim")
	dataDir := filepath.Join(home, ".local", "share", "nvim")

	for name, origin := range installed {
		gitDir := filepath.Join(dataDir, "lazy", name, ".git")
		writeFile(t, filepath.Join(gitDir, "config"), gitConfig(origin))
		writeFile(t, filepath.Join(gitDir, "HEAD"), testSHA+"\n")
	}
	if lock != "" {
		writeFile(t, filepath.Join(configDir, "lazy-lock.json"), lock)
	}

	return Env{HomeDir: home, ConfigDir: configDir, DataDir: dataDir}
}

// byName indexes discovered plugins for assertion.
func byName(plugins []Plugin) map[string]Plugin {
	m := make(map[string]Plugin, len(plugins))
	for _, p := range plugins {
		m[p.Name] = p
	}
	return m
}

func TestLazyDiscover_InstalledAndDeclared(t *testing.T) {
	env := lazyFixture(t,
		map[string]string{"snacks.nvim": "git@github.com:folke/snacks.nvim.git"},
		`{ "snacks.nvim": { "branch": "main", "commit": "`+testSHA+`" } }`,
	)

	got, err := newLazyManager().Discover(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	p := byName(got)["snacks.nvim"]
	if !p.Installed || !p.Declared {
		t.Errorf("Installed=%v Declared=%v, want both true", p.Installed, p.Declared)
	}
	if p.Repository != "https://github.com/folke/snacks.nvim" {
		t.Errorf("Repository = %q", p.Repository)
	}
	if p.Ecosystem != ecosystemGitHub || p.Owner != "folke" || p.Repo != "snacks.nvim" {
		t.Errorf("eco/owner/repo = %q/%q/%q", p.Ecosystem, p.Owner, p.Repo)
	}
	if p.Commit != testSHA || p.LockCommit != testSHA || p.LockBranch != "main" {
		t.Errorf("commit=%q lockCommit=%q lockBranch=%q", p.Commit, p.LockCommit, p.LockBranch)
	}
}

func TestLazyDiscover_InstalledOnly(t *testing.T) {
	env := lazyFixture(t,
		map[string]string{"copilot.lua": "https://github.com/zbirenbaum/copilot.lua.git"},
		"", // no lock file
	)

	got, err := newLazyManager().Discover(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	p := byName(got)["copilot.lua"]
	if !p.Installed || p.Declared {
		t.Errorf("Installed=%v Declared=%v, want true/false", p.Installed, p.Declared)
	}
	if p.Repository != "https://github.com/zbirenbaum/copilot.lua" {
		t.Errorf("Repository = %q", p.Repository)
	}
}

func TestLazyDiscover_DeclaredOnly(t *testing.T) {
	env := lazyFixture(t,
		nil, // nothing installed
		`{ "future.nvim": { "branch": "main", "commit": "`+testSHA+`" } }`,
	)

	got, err := newLazyManager().Discover(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	p := byName(got)["future.nvim"]
	if p.Installed || !p.Declared {
		t.Errorf("Installed=%v Declared=%v, want false/true", p.Installed, p.Declared)
	}
	if p.Repository != "" {
		t.Errorf("Repository = %q, want empty for declared-only", p.Repository)
	}
	if p.LockCommit != testSHA {
		t.Errorf("LockCommit = %q", p.LockCommit)
	}
}

func TestLazyDiscover_EmptyRoot(t *testing.T) {
	// No lazy dir, no lock file at all.
	home := t.TempDir()
	env := Env{
		HomeDir:   home,
		ConfigDir: filepath.Join(home, ".config", "nvim"),
		DataDir:   filepath.Join(home, ".local", "share", "nvim"),
	}
	got, err := newLazyManager().Discover(context.Background(), env)
	if err != nil {
		t.Fatalf("empty root should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no plugins, got %d", len(got))
	}
}

func TestLazyDiscover_MalformedLockDegrades(t *testing.T) {
	env := lazyFixture(t,
		map[string]string{"snacks.nvim": "git@github.com:folke/snacks.nvim.git"},
		`{ "snacks.nvim": { "commit": `, // truncated JSON
	)

	got, err := newLazyManager().Discover(context.Background(), env)
	if err == nil {
		t.Error("malformed lock file should surface an error")
	}
	// ...but installed clones are still emitted, undeclared.
	p := byName(got)["snacks.nvim"]
	if !p.Installed || p.Declared {
		t.Errorf("Installed=%v Declared=%v, want true/false on degrade", p.Installed, p.Declared)
	}
}

func TestLazyDiscover_SortedByName(t *testing.T) {
	env := lazyFixture(t,
		map[string]string{
			"zebra.nvim": "https://github.com/z/zebra.nvim.git",
			"alpha.nvim": "https://github.com/a/alpha.nvim.git",
			"mid.nvim":   "https://github.com/m/mid.nvim.git",
		},
		"",
	)
	got, err := newLazyManager().Discover(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha.nvim", "mid.nvim", "zebra.nvim"}
	for i, p := range got {
		if p.Name != want[i] {
			t.Errorf("position %d = %q, want %q", i, p.Name, want[i])
		}
	}
}
