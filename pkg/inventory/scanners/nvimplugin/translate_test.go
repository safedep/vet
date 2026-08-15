package nvimplugin

import (
	"testing"

	"github.com/safedep/vet/pkg/inventory"
)

func TestTranslate_InstalledGitHubPlugin(t *testing.T) {
	p := Plugin{
		Name:       "snacks.nvim",
		Repository: "https://github.com/folke/snacks.nvim",
		Ecosystem:  ecosystemGitHub,
		Owner:      "folke",
		Repo:       "snacks.nvim",
		Commit:     testSHA,
		LockCommit: testSHA,
		LockBranch: "main",
		InstallDir: "/home/u/.local/share/nvim/lazy/snacks.nvim",
		SourcePath: "/home/u/.config/nvim/lazy-lock.json",
		Declared:   true,
		Installed:  true,
	}
	item := translate(managerLazy, p)

	if item.Kind != inventory.KindIDEExtension {
		t.Errorf("Kind = %v, want KindIDEExtension", item.Kind)
	}
	if item.Name != "folke/snacks.nvim" {
		t.Errorf("Name = %q, want folke/snacks.nvim", item.Name)
	}
	if item.App != appName || item.Scope != inventory.ScopeSystem {
		t.Errorf("App=%q Scope=%v", item.App, item.Scope)
	}
	if item.ConfigPath != p.InstallDir {
		t.Errorf("ConfigPath = %q, want %q", item.ConfigPath, p.InstallDir)
	}
	if item.Enabled != nil {
		t.Errorf("Enabled = %v, want nil", item.Enabled)
	}

	want := map[string]string{
		metaKeyAppDisplay:    appDisplay,
		metaKeyPluginHost:    pluginHost,
		metaKeyPluginManager: managerLazy,
		metaKeyEcosystem:     ecosystemGitHub,
		metaKeyRepository:    "https://github.com/folke/snacks.nvim",
		metaKeyPurl:          "pkg:github/folke/snacks.nvim@" + testSHA,
		metaKeyCommit:        testSHA,
		metaKeyLockedCommit:  testSHA,
		metaKeyLockedBranch:  "main",
		metaKeyInstallPath:   p.InstallDir,
		metaKeyDeclared:      "true",
		metaKeyInstalled:     "true",
	}
	for k, v := range want {
		if item.Metadata[k] != v {
			t.Errorf("metadata[%q] = %q, want %q", k, item.Metadata[k], v)
		}
	}
	if len(item.Metadata) != len(want) {
		t.Errorf("metadata has %d keys, want %d: %v", len(item.Metadata), len(want), item.Metadata)
	}
}

func TestTranslate_GitEcosystemOmitsPurl(t *testing.T) {
	p := Plugin{
		Name:       "thing",
		Repository: "https://gitlab.example.com/team/thing",
		Ecosystem:  ecosystemGit,
		Owner:      "team",
		Repo:       "thing",
		Commit:     testSHA,
		InstallDir: "/d/lazy/thing",
		SourcePath: "/c/lazy-lock.json",
		Installed:  true,
	}
	item := translate(managerLazy, p)

	if _, ok := item.Metadata[metaKeyPurl]; ok {
		t.Error("git ecosystem must omit plugin.purl")
	}
	if item.Metadata[metaKeyRepository] != p.Repository {
		t.Errorf("repository = %q", item.Metadata[metaKeyRepository])
	}
	if item.Metadata[metaKeyEcosystem] != ecosystemGit {
		t.Errorf("ecosystem = %q", item.Metadata[metaKeyEcosystem])
	}
}

func TestTranslate_DeclaredOnlyFallsBackToLockKey(t *testing.T) {
	p := Plugin{
		Name:       "future.nvim",
		LockCommit: testSHA,
		LockBranch: "main",
		InstallDir: "/d/lazy/future.nvim",
		SourcePath: "/c/lazy-lock.json",
		Declared:   true,
		Installed:  false,
	}
	item := translate(managerLazy, p)

	if item.Name != "future.nvim" {
		t.Errorf("Name = %q, want lock-key fallback future.nvim", item.Name)
	}
	if item.Metadata[metaKeyInstalled] != "false" || item.Metadata[metaKeyDeclared] != "true" {
		t.Errorf("installed=%q declared=%q", item.Metadata[metaKeyInstalled], item.Metadata[metaKeyDeclared])
	}
	if _, ok := item.Metadata[metaKeyRepository]; ok {
		t.Error("declared-only plugin must omit plugin.repository")
	}
	if _, ok := item.Metadata[metaKeyCommit]; ok {
		t.Error("declared-only plugin has no actual commit")
	}
	if item.Metadata[metaKeyLockedCommit] != testSHA {
		t.Errorf("locked_commit = %q", item.Metadata[metaKeyLockedCommit])
	}
}

func TestTranslate_IdentityStableAcrossInstallTransition(t *testing.T) {
	// Same plugin before and after :Lazy sync: lock-only (name = lock key,
	// no owner/repo) then installed (display name becomes owner/repo). The
	// install dir and manager-local name are identical in both states, so
	// the identity must not change even though the display name does.
	lockOnly := Plugin{
		Name:       "snacks.nvim",
		InstallDir: "/home/u/.local/share/nvim/lazy/snacks.nvim",
		SourcePath: "/home/u/.config/nvim/lazy-lock.json",
		LockCommit: testSHA,
		Declared:   true,
	}
	installed := Plugin{
		Name:       "snacks.nvim",
		Owner:      "folke",
		Repo:       "snacks.nvim",
		Repository: "https://github.com/folke/snacks.nvim",
		Ecosystem:  ecosystemGitHub,
		Commit:     testSHA,
		InstallDir: "/home/u/.local/share/nvim/lazy/snacks.nvim",
		SourcePath: "/home/u/.config/nvim/lazy-lock.json",
		Installed:  true,
	}

	before := translate(managerLazy, lockOnly)
	after := translate(managerLazy, installed)

	if before.ItemIdentity != after.ItemIdentity {
		t.Errorf("identity changed across install transition: %q -> %q", before.ItemIdentity, after.ItemIdentity)
	}
	if before.SourceID != after.SourceID {
		t.Errorf("source id changed across install transition")
	}
	// Display name is allowed to change; identity is not.
	if before.Name != "snacks.nvim" || after.Name != "folke/snacks.nvim" {
		t.Errorf("display names = %q / %q", before.Name, after.Name)
	}
}

func TestTranslate_IdentityDeterministicAndStable(t *testing.T) {
	base := Plugin{
		Name: "snacks.nvim", Owner: "folke", Repo: "snacks.nvim",
		InstallDir: "/d/lazy/snacks.nvim", SourcePath: "/c/lazy-lock.json",
		Commit: testSHA, Installed: true,
	}
	a := translate(managerLazy, base)

	// Repeated translation is identical.
	if got := translate(managerLazy, base); got.ItemIdentity != a.ItemIdentity {
		t.Error("ItemIdentity not deterministic")
	}

	// Later declaring the same plugin (lock overlay) must not change
	// identity: ConfigPath is the install dir, stable across declaration.
	declared := base
	declared.Declared = true
	declared.LockCommit = testSHA
	if got := translate(managerLazy, declared); got.ItemIdentity != a.ItemIdentity {
		t.Error("ItemIdentity changed when plugin became declared")
	}
	if got := translate(managerLazy, declared); got.SourceID != a.SourceID {
		t.Error("SourceID changed when plugin became declared")
	}
}
