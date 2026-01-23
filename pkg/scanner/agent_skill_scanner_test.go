package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultAgentSkillScannerConfig(t *testing.T) {
	config := DefaultAgentSkillScannerConfig()

	assert.True(t, config.FailFast, "Default config should have FailFast enabled")
	assert.Equal(t, "HIGH", config.MinimumConfidence, "Default minimum confidence should be HIGH")
}

func TestNewAgentSkillScanner(t *testing.T) {
	config := DefaultAgentSkillScannerConfig()

	scanner := NewAgentSkillScanner(
		config,
		nil, // reader
		nil, // enricher
		nil, // analyzer
		nil, // reporters
	)

	assert.NotNil(t, scanner)
	assert.Equal(t, config, scanner.config)
}

func TestAgentSkillScannerErrorState(t *testing.T) {
	scanner := &agentSkillScanner{}

	// Initial state should have no error
	assert.Nil(t, scanner.error())

	// Set an error
	testErr := assert.AnError
	scanner.failWith(testErr)

	// Error should be retrievable
	assert.Equal(t, testErr, scanner.error())
}
