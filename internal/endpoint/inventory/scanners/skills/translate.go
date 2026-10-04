// Package skills is an inventory.Scanner that discovers agent skill
// directories from all supported AI coding agents.
package skills

import "github.com/safedep/vet/v2/internal/endpoint/inventory"

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
		ItemIdentity: inventory.ItemIdentity(s.App, inventory.KindAgentSkill, s.Scope, s.Name, s.ConfigPath),
		SourceID:     inventory.SourceID(s.App, s.SkillsDir),
		Name:         s.Name,
		App:          s.App,
		Scope:        s.Scope,
		ConfigPath:   s.ConfigPath,
		Metadata:     meta,
	}
}
