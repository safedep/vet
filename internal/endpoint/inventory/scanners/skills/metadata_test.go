package skills

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadSkillFrontmatterExtractsNameAndDescription(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(`---
name: yaad
description: "Local memory engine for humans and agents."
---

# Body content here
`), 0o644))

	meta := readSkillFrontmatter(dir)
	assert.Equal(t, "yaad", meta.Name)
	assert.Equal(t, "Local memory engine for humans and agents.", meta.Description)
}

func TestReadSkillFrontmatterHandlesMissingFile(t *testing.T) {
	meta := readSkillFrontmatter(t.TempDir())
	assert.Empty(t, meta.Name)
	assert.Empty(t, meta.Description)
}

func TestReadSkillFrontmatterHandlesNoFrontmatter(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(`# Just a heading

No frontmatter here.
`), 0o644))

	meta := readSkillFrontmatter(dir)
	assert.Empty(t, meta.Name)
	assert.Empty(t, meta.Description)
}

func TestReadSkillFrontmatterHandlesMultilineDescription(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(`---
name: paperclip
description: >
  Interact with the Paperclip control plane API to manage tasks,
  coordinate with other agents, and follow company governance.
---
`), 0o644))

	meta := readSkillFrontmatter(dir)
	assert.Equal(t, "paperclip", meta.Name)
	assert.NotEmpty(t, meta.Description)
}

func TestTranslatePopulatesDescriptionMetadata(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(`---
name: my-skill
description: "Does something useful."
---
`), 0o644))

	item := translate(&skill{
		App:        "claude-code",
		Name:       "my-skill",
		ConfigPath: dir,
		SkillsDir:  filepath.Dir(dir),
	})

	assert.Equal(t, "Does something useful.", item.Metadata["skill.description"])
}

func TestTranslatePopulatesDisplayNameWhenDifferentFromDirName(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(`---
name: My Fancy Skill
description: "A skill."
---
`), 0o644))

	item := translate(&skill{
		App:        "claude-code",
		Name:       "my-fancy-skill",
		ConfigPath: dir,
		SkillsDir:  filepath.Dir(dir),
	})

	assert.Equal(t, "My Fancy Skill", item.Metadata["skill.display_name"])
}

func TestTranslateOmitsDisplayNameWhenSameAsDirName(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(`---
name: my-skill
description: "A skill."
---
`), 0o644))

	item := translate(&skill{
		App:        "claude-code",
		Name:       "my-skill",
		ConfigPath: dir,
		SkillsDir:  filepath.Dir(dir),
	})

	_, hasDisplayName := item.Metadata["skill.display_name"]
	assert.False(t, hasDisplayName, "display_name must be omitted when it matches the dir name")
}
