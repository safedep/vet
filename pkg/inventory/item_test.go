package inventory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKindEnumValues(t *testing.T) {
	// Mirror the proto InventoryItemKind enum 1:1.
	tests := []struct {
		name string
		kind Kind
		want int
	}{
		{"unspecified", KindUnspecified, 0},
		{"mcp_server", KindMCPServer, 1},
		{"coding_agent", KindCodingAgent, 2},
		{"ai_extension", KindAIExtension, 3},
		{"cli_tool", KindCLITool, 4},
		{"project_config", KindProjectConfig, 5},
		{"browser_extension", KindBrowserExtension, 6},
		{"ide_extension", KindIDEExtension, 7},
		{"agent_plugin", KindAgentPlugin, 8},
		{"agent_skill", KindAgentSkill, 9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, int(tt.kind))
		})
	}
}

func TestScopeEnumValues(t *testing.T) {
	tests := []struct {
		name  string
		scope Scope
		want  int
	}{
		{"unspecified", ScopeUnspecified, 0},
		{"system", ScopeSystem, 1},
		{"project", ScopeProject, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, int(tt.scope))
		})
	}
}

func TestItemZeroValue(t *testing.T) {
	var item Item
	assert.Equal(t, KindUnspecified, item.Kind)
	assert.Equal(t, ScopeUnspecified, item.Scope)
	assert.Empty(t, item.ItemIdentity)
	assert.Empty(t, item.SourceID)
	assert.Empty(t, item.Name)
	assert.Empty(t, item.App)
	assert.Empty(t, item.ConfigPath)
	assert.Nil(t, item.Enabled)
	assert.Nil(t, item.MCPServer)
	assert.Nil(t, item.Agent)
	assert.Nil(t, item.Metadata)
}

func TestItemWithEnabledPointer(t *testing.T) {
	enabled := true
	item := Item{Enabled: &enabled}
	if assert.NotNil(t, item.Enabled) {
		assert.True(t, *item.Enabled)
	}
}

func TestMCPServerDetailZeroValue(t *testing.T) {
	var detail MCPServerDetail
	assert.Equal(t, TransportUnspecified, detail.Transport)
	assert.Empty(t, detail.Command)
	assert.Nil(t, detail.Args)
	assert.Empty(t, detail.URL)
	assert.Nil(t, detail.EnvVarNames)
	assert.Nil(t, detail.HeaderNames)
	assert.Nil(t, detail.AllowedTools)
	assert.Nil(t, detail.AllowedResources)
}

func TestTransportEnumValues(t *testing.T) {
	tests := []struct {
		name      string
		transport Transport
		want      int
	}{
		{"unspecified", TransportUnspecified, 0},
		{"stdio", TransportStdio, 1},
		{"sse", TransportSSE, 2},
		{"streamable_http", TransportStreamableHTTP, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, int(tt.transport))
		})
	}
}

func TestAgentDetailZeroValue(t *testing.T) {
	var detail AgentDetail
	assert.Empty(t, detail.Version)
	assert.Empty(t, detail.PermissionMode)
	assert.Nil(t, detail.InstructionFiles)
	assert.Empty(t, detail.Model)
	assert.Empty(t, detail.APIKeyEnvName)
}
