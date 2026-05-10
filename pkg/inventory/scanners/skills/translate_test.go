package skills

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/pkg/inventory"
)

func TestTranslateBasicFields(t *testing.T) {
	s := &skill{
		App:        "claude-code",
		Name:       "yaad",
		Scope:      inventory.ScopeProject,
		ConfigPath: "/work/.claude/skills/yaad",
		SkillsDir:  "/work/.claude/skills",
	}
	item := translate(s)

	assert.Equal(t, inventory.KindAgentSkill, item.Kind)
	assert.Equal(t, "yaad", item.Name)
	assert.Equal(t, "claude-code", item.App)
	assert.Equal(t, inventory.ScopeProject, item.Scope)
	assert.Equal(t, "/work/.claude/skills/yaad", item.ConfigPath)
	assert.NotEmpty(t, item.ItemIdentity)
	assert.NotEmpty(t, item.SourceID)
	assert.Nil(t, item.Enabled)
	assert.Equal(t, map[string]string{"skill.path": "/work/.claude/skills/yaad"}, item.Metadata)
	assert.Nil(t, item.MCPServer)
	assert.Nil(t, item.Agent)
}

func TestTranslateItemIdentityDeterministic(t *testing.T) {
	s := &skill{
		App:        "cursor",
		Name:       "my-skill",
		Scope:      inventory.ScopeSystem,
		ConfigPath: "/home/u/.cursor/skills/my-skill",
		SkillsDir:  "/home/u/.cursor/skills",
	}
	assert.Equal(t, translate(s).ItemIdentity, translate(s).ItemIdentity)
}

func TestTranslateItemIdentityUnique(t *testing.T) {
	a := &skill{
		App: "cursor", Name: "skill-a", Scope: inventory.ScopeSystem,
		ConfigPath: "/home/u/.cursor/skills/skill-a", SkillsDir: "/home/u/.cursor/skills",
	}
	b := &skill{
		App: "cursor", Name: "skill-b", Scope: inventory.ScopeSystem,
		ConfigPath: "/home/u/.cursor/skills/skill-b", SkillsDir: "/home/u/.cursor/skills",
	}
	assert.NotEqual(t, translate(a).ItemIdentity, translate(b).ItemIdentity)
}

func TestTranslateSourceIDGroupsSkillsInSameDir(t *testing.T) {
	dir := "/work/.claude/skills"
	a := &skill{
		App: "claude-code", Name: "skill-a", Scope: inventory.ScopeProject,
		ConfigPath: dir + "/skill-a", SkillsDir: dir,
	}
	b := &skill{
		App: "claude-code", Name: "skill-b", Scope: inventory.ScopeProject,
		ConfigPath: dir + "/skill-b", SkillsDir: dir,
	}
	assert.Equal(t, translate(a).SourceID, translate(b).SourceID)
}
