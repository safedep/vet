package nvimplugin

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/safedep/vet/pkg/inventory"
)

// fakeManager is a Manager stub returning canned results.
type fakeManager struct {
	name     string
	plugins  []Plugin
	discover error
}

func (f *fakeManager) Name() string { return f.name }
func (f *fakeManager) Discover(_ context.Context, _ Env) ([]Plugin, error) {
	return f.plugins, f.discover
}

// collect runs a scan against a temp HomeDir and returns emitted items.
func collect(t *testing.T, a *adapter, scopes []inventory.Scope) ([]*inventory.Item, error) {
	t.Helper()
	var items []*inventory.Item
	err := a.Scan(context.Background(),
		inventory.ScanConfig{HomeDir: t.TempDir(), Scopes: scopes},
		func(item *inventory.Item) error {
			items = append(items, item)
			return nil
		})
	return items, err
}

func TestScan_ScopeGating(t *testing.T) {
	a := newAdapter(&fakeManager{name: "lazy.nvim", plugins: []Plugin{{Name: "x", InstallDir: "/d/x"}}})

	// Project scope only: nvim plugins are system-scoped, so nothing emits.
	items, err := collect(t, a, []inventory.Scope{inventory.ScopeProject})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Errorf("project-only scope emitted %d items, want 0", len(items))
	}

	// System scope enabled: the plugin emits.
	items, err = collect(t, a, []inventory.Scope{inventory.ScopeSystem})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Errorf("system scope emitted %d items, want 1", len(items))
	}
}

func TestScan_DeterministicOrdering(t *testing.T) {
	a := newAdapter(
		&fakeManager{name: "lazy.nvim", plugins: []Plugin{
			{Name: "zebra", InstallDir: "/d/zebra"},
			{Name: "alpha", InstallDir: "/d/alpha"},
		}},
		&fakeManager{name: "packer", plugins: []Plugin{
			{Name: "mid", InstallDir: "/d/mid"},
		}},
	)
	items, err := collect(t, a, nil) // nil scopes = all enabled
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha", "mid", "zebra"}
	if len(items) != len(want) {
		t.Fatalf("emitted %d items, want %d", len(items), len(want))
	}
	for i, item := range items {
		if item.Name != want[i] {
			t.Errorf("position %d = %q, want %q", i, item.Name, want[i])
		}
	}
}

func TestScan_ErrorAggregationDoesNotSuppressResults(t *testing.T) {
	a := newAdapter(
		&fakeManager{name: "broken", discover: errors.New("boom")},
		&fakeManager{name: "empty"}, // (nil, nil) — must not short-circuit
		&fakeManager{name: "lazy.nvim", plugins: []Plugin{{Name: "ok", InstallDir: "/d/ok"}}},
	)
	items, err := collect(t, a, nil)

	if err == nil {
		t.Fatal("expected aggregated error from the broken manager")
	}
	if !strings.Contains(err.Error(), "broken") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("error missing manager context: %v", err)
	}
	// The healthy manager's plugin is still emitted despite the failure.
	if len(items) != 1 || items[0].Name != "ok" {
		t.Errorf("expected the healthy plugin emitted, got %+v", items)
	}
}

func TestScan_EmitErrorStops(t *testing.T) {
	a := newAdapter(&fakeManager{name: "lazy.nvim", plugins: []Plugin{
		{Name: "a", InstallDir: "/d/a"},
		{Name: "b", InstallDir: "/d/b"},
	}})
	sentinel := errors.New("sink closed")
	count := 0
	err := a.Scan(context.Background(),
		inventory.ScanConfig{HomeDir: t.TempDir()},
		func(*inventory.Item) error { count++; return sentinel })

	if !errors.Is(err, sentinel) {
		t.Errorf("Scan should return the emit error, got %v", err)
	}
	if count != 1 {
		t.Errorf("emit called %d times, want 1 (stop on first error)", count)
	}
}

func TestScan_EndToEndWithLazyManager(t *testing.T) {
	// Exercises the production manager set through resolveEnv against a real
	// on-disk fixture keyed off cfg.HomeDir. Pin NVIM_APPNAME so the
	// resolved data dir matches the fixture regardless of ambient env.
	t.Setenv("NVIM_APPNAME", "")
	env := lazyFixture(t,
		map[string]string{"snacks.nvim": "git@github.com:folke/snacks.nvim.git"},
		`{ "snacks.nvim": { "branch": "main", "commit": "`+testSHA+`" } }`,
	)

	var items []*inventory.Item
	err := New().Scan(context.Background(),
		inventory.ScanConfig{HomeDir: env.HomeDir},
		func(item *inventory.Item) error { items = append(items, item); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("emitted %d items, want 1", len(items))
	}
	item := items[0]
	if item.Name != "folke/snacks.nvim" || item.App != appName {
		t.Errorf("Name=%q App=%q", item.Name, item.App)
	}
	if item.Metadata[metaKeyPurl] != "pkg:github/folke/snacks.nvim@"+testSHA {
		t.Errorf("purl = %q", item.Metadata[metaKeyPurl])
	}
	if item.Metadata[metaKeyPluginManager] != managerLazy {
		t.Errorf("manager = %q", item.Metadata[metaKeyPluginManager])
	}
}
