package skills

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type skillFrontmatter struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// readSkillFrontmatter parses the YAML frontmatter from SKILL.md in skillDir.
// Returns zero-value struct if the file is absent or has no frontmatter.
func readSkillFrontmatter(skillDir string) skillFrontmatter {
	f, err := os.Open(filepath.Join(skillDir, "SKILL.md"))
	if err != nil {
		return skillFrontmatter{}
	}
	defer func() { _ = f.Close() }()

	// Extract content between the opening and closing --- delimiters.
	var lines []string
	scanner := bufio.NewScanner(f)
	inFrontmatter := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "---" {
			if !inFrontmatter {
				inFrontmatter = true
				continue
			}
			break // closing delimiter
		}
		if inFrontmatter {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return skillFrontmatter{}
	}

	var fm skillFrontmatter
	_ = yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &fm)
	return fm
}
