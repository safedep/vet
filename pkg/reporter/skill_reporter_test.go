package reporter

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/pkg/models"
)

func TestDefaultSkillReporterConfig(t *testing.T) {
	config := DefaultSkillReporterConfig()
	assert.True(t, config.ShowEvidence, "Default config should show evidence")
}

func TestNewSkillReporter(t *testing.T) {
	config := DefaultSkillReporterConfig()
	reporter := NewSkillReporter(config)

	assert.NotNil(t, reporter)
	assert.Equal(t, config, reporter.config)
	assert.NotNil(t, reporter.events)
	assert.Equal(t, 0, len(reporter.events))
}

func TestSkillReporterName(t *testing.T) {
	reporter := NewSkillReporter(DefaultSkillReporterConfig())
	assert.Equal(t, "Agent Skill Reporter", reporter.Name())
}

func TestSkillReporterAddManifest(t *testing.T) {
	reporter := NewSkillReporter(DefaultSkillReporterConfig())
	manifest := models.NewPackageManifestFromLocal("/test/path", models.EcosystemGitHubActions)

	reporter.AddManifest(manifest)

	assert.NotNil(t, reporter.manifest)
	assert.Equal(t, manifest, reporter.manifest)
}

func TestSkillReporterWrapText(t *testing.T) {
	reporter := NewSkillReporter(DefaultSkillReporterConfig())

	tests := []struct {
		name     string
		input    string
		width    int
		expected []string
	}{
		{
			name:     "short text",
			input:    "Hello world",
			width:    20,
			expected: []string{"Hello world"},
		},
		{
			name:     "text exactly at width",
			input:    "Hello",
			width:    5,
			expected: []string{"Hello"},
		},
		{
			name:  "text needs wrapping",
			input: "This is a long sentence that needs to be wrapped",
			width: 20,
			expected: []string{
				"This is a long",
				"sentence that needs",
				"to be wrapped",
			},
		},
		{
			name:     "empty text",
			input:    "",
			width:    20,
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reporter.wrapText(tt.input, tt.width)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSkillReporterColorizeConfidence(t *testing.T) {
	reporter := NewSkillReporter(DefaultSkillReporterConfig())

	tests := []struct {
		name       string
		confidence string
	}{
		{
			name:       "high confidence",
			confidence: "HIGH",
		},
		{
			name:       "medium confidence",
			confidence: "MEDIUM",
		},
		{
			name:       "low confidence",
			confidence: "LOW",
		},
		{
			name:       "unknown confidence",
			confidence: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reporter.colorizeConfidence(tt.confidence)
			// Just verify it returns a non-empty string
			// Actual color codes are implementation details
			assert.NotEmpty(t, result)
		})
	}
}
