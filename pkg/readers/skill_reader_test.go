package readers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSkillReaderParseSkillSpec(t *testing.T) {
	tests := []struct {
		name      string
		skillSpec string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{
			name:      "owner/repo format",
			skillSpec: "safedep/skills",
			wantOwner: "safedep",
			wantRepo:  "skills",
			wantErr:   false,
		},
		{
			name:      "github url https",
			skillSpec: "https://github.com/vercel/ai-sdk",
			wantOwner: "vercel",
			wantRepo:  "ai-sdk",
			wantErr:   false,
		},
		{
			name:      "github url with .git",
			skillSpec: "https://github.com/openai/swarm.git",
			wantOwner: "openai",
			wantRepo:  "swarm",
			wantErr:   false,
		},
		{
			name:      "invalid format - single word",
			skillSpec: "invalid",
			wantErr:   true,
		},
		{
			name:      "invalid format - too many slashes",
			skillSpec: "owner/repo/extra",
			wantErr:   true,
		},
		{
			name:      "non-github url",
			skillSpec: "https://gitlab.com/owner/repo",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &skillReader{
				config: SkillReaderConfig{
					SkillSpec: tt.skillSpec,
				},
			}

			gitURL, err := reader.parseSkillSpec()

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantOwner, gitURL.GetOwnerName())
			assert.Equal(t, tt.wantRepo, gitURL.GetRepoName())
			assert.Equal(t, "github.com", gitURL.GetHostName())
		})
	}
}

func TestSkillReaderApplicationName(t *testing.T) {
	tests := []struct {
		name      string
		skillSpec string
		wantName  string
	}{
		{
			name:      "owner/repo format",
			skillSpec: "safedep/skills",
			wantName:  "skills",
		},
		{
			name:      "github url",
			skillSpec: "https://github.com/vercel/ai-sdk",
			wantName:  "ai-sdk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &skillReader{
				config: SkillReaderConfig{
					SkillSpec: tt.skillSpec,
				},
			}

			name, err := reader.ApplicationName()
			assert.NoError(t, err)
			assert.Equal(t, tt.wantName, name)
		})
	}
}

func TestSkillReaderName(t *testing.T) {
	reader := &skillReader{}
	assert.Equal(t, "Agent Skill Reader", reader.Name())
}

func TestNewSkillReaderValidation(t *testing.T) {
	tests := []struct {
		name      string
		skillSpec string
		wantErr   bool
	}{
		{
			name:      "valid skill spec",
			skillSpec: "safedep/skills",
			wantErr:   false,
		},
		{
			name:      "empty skill spec",
			skillSpec: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSkillReader(nil, SkillReaderConfig{
				SkillSpec: tt.skillSpec,
			})

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
