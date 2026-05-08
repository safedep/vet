package skills

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/pkg/inventory"
)

func TestAdapterName(t *testing.T) {
	assert.Equal(t, scannerName, New().Name())
}

func TestAdapterScanEmitsSkillsFromProjectDir(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, ".claude", "skills", "yaad"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, ".claude", "skills", "stop-slop"), 0o755))

	var emitted []*inventory.Item
	err := New().Scan(context.Background(), inventory.ScanConfig{
		ProjectDir: tmp,
		Scopes:     []inventory.Scope{inventory.ScopeProject},
	}, func(item *inventory.Item) error {
		if item.App == "claude-code" {
			emitted = append(emitted, item)
		}
		return nil
	})
	require.NoError(t, err)
	require.Len(t, emitted, 2)

	names := []string{emitted[0].Name, emitted[1].Name}
	assert.ElementsMatch(t, []string{"yaad", "stop-slop"}, names)
	assert.Equal(t, inventory.KindAgentSkill, emitted[0].Kind)
	assert.Equal(t, inventory.ScopeProject, emitted[0].Scope)
	assert.Equal(t, "claude-code", emitted[0].App)
}

func TestAdapterScanEmitsSkillsFromGlobalDir(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, ".claude", "skills", "my-skill"), 0o755))

	var emitted []*inventory.Item
	err := New().Scan(context.Background(), inventory.ScanConfig{
		HomeDir: tmp,
		Scopes:  []inventory.Scope{inventory.ScopeSystem},
	}, func(item *inventory.Item) error {
		if item.App == "claude-code" {
			emitted = append(emitted, item)
		}
		return nil
	})
	require.NoError(t, err)
	require.Len(t, emitted, 1)
	assert.Equal(t, "my-skill", emitted[0].Name)
	assert.Equal(t, inventory.ScopeSystem, emitted[0].Scope)
}

func TestAdapterScanSkipsFilesInSkillsDir(t *testing.T) {
	tmp := t.TempDir()
	skillsDir := filepath.Join(tmp, ".claude", "skills")
	require.NoError(t, os.MkdirAll(skillsDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(skillsDir, "README.md"), []byte("x"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(skillsDir, "real-skill"), 0o755))

	var emitted []*inventory.Item
	err := New().Scan(context.Background(), inventory.ScanConfig{
		ProjectDir: tmp,
		Scopes:     []inventory.Scope{inventory.ScopeProject},
	}, func(item *inventory.Item) error {
		if item.App == "claude-code" {
			emitted = append(emitted, item)
		}
		return nil
	})
	require.NoError(t, err)
	require.Len(t, emitted, 1)
	assert.Equal(t, "real-skill", emitted[0].Name)
}

func TestAdapterScanSkipsMissingDirectory(t *testing.T) {
	err := New().Scan(context.Background(), inventory.ScanConfig{
		ProjectDir: "/nonexistent/path/that/does/not/exist",
		Scopes:     []inventory.Scope{inventory.ScopeProject},
	}, func(*inventory.Item) error { return nil })
	require.NoError(t, err, "missing directories must not cause an error")
}

func TestAdapterScanPropagatesEmitError(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, ".claude", "skills", "skill-a"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, ".claude", "skills", "skill-b"), 0o755))

	stop := errors.New("stop")
	count := 0
	err := New().Scan(context.Background(), inventory.ScanConfig{
		ProjectDir: tmp,
		Scopes:     []inventory.Scope{inventory.ScopeProject},
	}, func(item *inventory.Item) error {
		if item.App != "claude-code" {
			return nil
		}
		count++
		return stop
	})
	require.ErrorIs(t, err, stop)
	assert.Equal(t, 1, count, "emit error must stop the scan immediately")
}

func TestAdapterScanRespectsProjectScopeOnly(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, ".claude", "skills", "proj-skill"), 0o755))

	var scopes []inventory.Scope
	err := New().Scan(context.Background(), inventory.ScanConfig{
		ProjectDir: tmp,
		HomeDir:    tmp,
		Scopes:     []inventory.Scope{inventory.ScopeProject},
	}, func(item *inventory.Item) error {
		scopes = append(scopes, item.Scope)
		return nil
	})
	require.NoError(t, err)
	for _, s := range scopes {
		assert.Equal(t, inventory.ScopeProject, s, "only project-scoped items expected")
	}
}

func TestAdapterScanEmitsClaudePluginSkills(t *testing.T) {
	tmp := t.TempDir()
	// Simulate ~/.claude/plugins/cache/<org>/<plugin>/<version>/skills/<skill>/
	skillDir := filepath.Join(tmp, ".claude", "plugins", "cache", "acme-org", "my-plugin", "1.0.0", "skills")
	require.NoError(t, os.MkdirAll(filepath.Join(skillDir, "skill-alpha"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(skillDir, "skill-beta"), 0o755))

	var emitted []*inventory.Item
	err := New().Scan(context.Background(), inventory.ScanConfig{
		HomeDir: tmp,
		Scopes:  []inventory.Scope{inventory.ScopeSystem},
	}, func(item *inventory.Item) error {
		emitted = append(emitted, item)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, emitted, 2)

	names := []string{emitted[0].Name, emitted[1].Name}
	assert.ElementsMatch(t, []string{"my-plugin/skill-alpha", "my-plugin/skill-beta"}, names)
	assert.Equal(t, "claude-code", emitted[0].App)
	assert.Equal(t, inventory.KindAgentSkill, emitted[0].Kind)
	assert.Equal(t, inventory.ScopeSystem, emitted[0].Scope)
	assert.Equal(t, emitted[0].ConfigPath, emitted[0].Metadata["skill.path"])
}

func TestAdapterScanEmitsClaudeMarketplaceSkills(t *testing.T) {
	tmp := t.TempDir()
	// Simulate ~/.claude/plugins/marketplaces/<marketplace>/plugins/<plugin>/skills/<skill>/
	skillDir := filepath.Join(tmp, ".claude", "plugins", "marketplaces", "my-marketplace", "plugins", "my-plugin", "skills")
	require.NoError(t, os.MkdirAll(filepath.Join(skillDir, "skill-one"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(skillDir, "skill-two"), 0o755))

	var emitted []*inventory.Item
	err := New().Scan(context.Background(), inventory.ScanConfig{
		HomeDir: tmp,
		Scopes:  []inventory.Scope{inventory.ScopeSystem},
	}, func(item *inventory.Item) error {
		emitted = append(emitted, item)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, emitted, 2)

	names := []string{emitted[0].Name, emitted[1].Name}
	assert.ElementsMatch(t, []string{"my-plugin/skill-one", "my-plugin/skill-two"}, names)
	assert.Equal(t, "claude-code", emitted[0].App)
	assert.Equal(t, inventory.KindAgentSkill, emitted[0].Kind)
	assert.Equal(t, inventory.ScopeSystem, emitted[0].Scope)
	assert.Equal(t, emitted[0].ConfigPath, emitted[0].Metadata["skill.path"])
}

func TestAdapterScanRespectsSystemScopeOnly(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, ".claude", "skills", "sys-skill"), 0o755))

	var scopes []inventory.Scope
	err := New().Scan(context.Background(), inventory.ScanConfig{
		ProjectDir: tmp,
		HomeDir:    tmp,
		Scopes:     []inventory.Scope{inventory.ScopeSystem},
	}, func(item *inventory.Item) error {
		scopes = append(scopes, item.Scope)
		return nil
	})
	require.NoError(t, err)
	for _, s := range scopes {
		assert.Equal(t, inventory.ScopeSystem, s, "only system-scoped items expected")
	}
}
