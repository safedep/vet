// Package skills is an inventory.Scanner that discovers agent skill
// directories from all supported AI coding agents.
package skills

import (
	"fmt"
	"hash/fnv"

	"github.com/safedep/vet/pkg/inventory"
)

// skill is the internal representation of a single discovered skill directory.
type skill struct {
	App        string
	Name       string
	Scope      inventory.Scope
	ConfigPath string // absolute path to the skill directory
	SkillsDir  string // parent directory — used for SourceID grouping
}

// translate converts a discovered skill to a wire-decoupled inventory.Item.
func translate(s *skill) *inventory.Item {
	meta := map[string]string{"skill.path": s.ConfigPath}

	fm := readSkillFrontmatter(s.ConfigPath)
	if fm.Description != "" {
		meta["skill.description"] = fm.Description
	}
	if fm.Name != "" && fm.Name != s.Name {
		meta["skill.display_name"] = fm.Name
	}

	return &inventory.Item{
		Kind:         inventory.KindAgentSkill,
		ItemIdentity: itemIdentity(s.App, inventory.KindAgentSkill, s.Scope, s.Name, s.ConfigPath),
		SourceID:     sourceID(s.App, s.SkillsDir),
		Name:         s.Name,
		App:          s.App,
		Scope:        s.Scope,
		ConfigPath:   s.ConfigPath,
		Metadata:     meta,
	}
}

// itemIdentity computes the FNV-64a dedup key: hash(app/kind/scope/name/config_path).
// Mirrors the scheme described in inventory.Item.ItemIdentity documentation.
func itemIdentity(app string, kind inventory.Kind, scope inventory.Scope, name, configPath string) string {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%s/%d/%d/%s/%s", app, kind, scope, name, configPath)
	return fmt.Sprintf("%x", h.Sum64())
}

// sourceID groups skills emitted from the same agent skills directory.
// Uses FNV-64a so the result is always ≤16 hex chars, satisfying the
// backend's 100-character limit even for deep plugin paths.
func sourceID(app, skillsDir string) string {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%s:%s", app, skillsDir)
	return fmt.Sprintf("%x", h.Sum64())
}
