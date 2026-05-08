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
// Pure function: no I/O, no globals, deterministic.
func translate(s *skill) *inventory.Item {
	return &inventory.Item{
		Kind:         inventory.KindAgentSkill,
		ItemIdentity: itemIdentity(s.App, inventory.KindAgentSkill, s.Scope, s.Name, s.ConfigPath),
		SourceID:     sourceID(s.App, s.SkillsDir),
		Name:         s.Name,
		App:          s.App,
		Scope:        s.Scope,
		ConfigPath:   s.ConfigPath,
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
func sourceID(app, skillsDir string) string {
	return fmt.Sprintf("%s:%s", app, skillsDir)
}
