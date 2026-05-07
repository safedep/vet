package ai

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/cmd/endpoint"
)

func TestDiscoverCommand_DelegatesToRunAITool(t *testing.T) {
	original := runAITool
	t.Cleanup(func() { runAITool = original })

	var captured endpoint.AliasOptions
	runAITool = func(_ context.Context, opts endpoint.AliasOptions) error {
		captured = opts
		return nil
	}

	cmd := newDiscoverCommand()
	cmd.SetArgs([]string{
		"--scope", "system",
		"--project-dir", "/tmp/foo",
		"--report-json", "/tmp/inv.json",
		"--silent",
		"--drain-timeout", "10s",
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	require.NoError(t, cmd.Execute())

	assert.Equal(t, []string{"system"}, captured.Scopes)
	assert.Equal(t, "/tmp/foo", captured.ProjectDir)
	assert.Equal(t, "/tmp/inv.json", captured.ReportJSON)
	assert.True(t, captured.Silent)
	assert.Equal(t, 10*time.Second, captured.DrainTimeout)
}

func TestDiscoverCommand_DefaultDrainTimeout(t *testing.T) {
	original := runAITool
	t.Cleanup(func() { runAITool = original })

	var captured endpoint.AliasOptions
	runAITool = func(_ context.Context, opts endpoint.AliasOptions) error {
		captured = opts
		return nil
	}

	cmd := newDiscoverCommand()
	cmd.SetArgs(nil)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	require.NoError(t, cmd.Execute())

	assert.Equal(t, endpoint.DefaultDrainTimeout, captured.DrainTimeout)
}
