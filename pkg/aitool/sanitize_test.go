package aitool

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeArgs_RedactsSecretPatterns(t *testing.T) {
	args := []string{
		"--token=sk-ant-12345",
		"--api-key=my-secret-key",
		"--password=hunter2",
		"--secret=top-secret",
		"--credentials=cred-value",
	}

	sanitized := SanitizeArgs(args)

	assert.Equal(t, "--token=<REDACTED>", sanitized[0])
	assert.Equal(t, "--api-key=<REDACTED>", sanitized[1])
	assert.Equal(t, "--password=<REDACTED>", sanitized[2])
	assert.Equal(t, "--secret=<REDACTED>", sanitized[3])
	assert.Equal(t, "--credentials=<REDACTED>", sanitized[4])
}

func TestSanitizeArgs_PreservesNonSecretArgs(t *testing.T) {
	args := []string{"-y", "@safedep/mcp", "--port=8080", "server.js"}
	sanitized := SanitizeArgs(args)
	assert.Equal(t, args, sanitized)
}

func TestSanitizeArgs_CaseInsensitive(t *testing.T) {
	args := []string{"--TOKEN=secret", "--Api-Key=key123"}
	sanitized := SanitizeArgs(args)
	assert.Equal(t, "--TOKEN=<REDACTED>", sanitized[0])
	assert.Equal(t, "--Api-Key=<REDACTED>", sanitized[1])
}

func TestSanitizeArgs_EmptySlice(t *testing.T) {
	sanitized := SanitizeArgs([]string{})
	assert.Empty(t, sanitized)
}

func TestSanitizeArgs_NilSlice(t *testing.T) {
	sanitized := SanitizeArgs(nil)
	assert.Nil(t, sanitized, "nil input should return nil, not empty slice")
}
