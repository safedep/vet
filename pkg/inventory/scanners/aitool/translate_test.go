package aitool

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/pkg/aitool"
	"github.com/safedep/vet/pkg/inventory"
)

func TestTranslateNilReturnsNil(t *testing.T) {
	assert.Nil(t, translate(nil))
}

func TestTranslateMCPServer(t *testing.T) {
	enabled := true
	tool := &aitool.AITool{
		Name:       "anthropic-mcp",
		Type:       aitool.AIToolTypeMCPServer,
		Scope:      aitool.AIToolScopeProject,
		App:        "claude_code",
		AppDisplay: "Claude Code",
		ConfigPath: "/work/repo/.mcp.json",
		ID:         "fixture-id",
		SourceID:   "fixture-source",
		Enabled:    &enabled,
		MCPServer: &aitool.MCPServerConfig{
			Transport:        aitool.MCPTransportStdio,
			Command:          "npx",
			Args:             []string{"-y", "@anthropic/mcp"},
			EnvVarNames:      []string{"ANTHROPIC_API_KEY"},
			AllowedTools:     []string{"read"},
			AllowedResources: []string{"file://*"},
		},
	}

	item := translate(tool)
	require.NotNil(t, item)
	assert.Equal(t, inventory.KindMCPServer, item.Kind)
	assert.Equal(t, inventory.ScopeProject, item.Scope)
	assert.Equal(t, "anthropic-mcp", item.Name)
	assert.Equal(t, "claude_code", item.App)
	assert.Equal(t, "/work/repo/.mcp.json", item.ConfigPath)
	require.NotNil(t, item.Enabled)
	assert.True(t, *item.Enabled)
	assert.Equal(t, "fixture-id", item.ItemIdentity)
	assert.Equal(t, "fixture-source", item.SourceID)

	require.NotNil(t, item.MCPServer)
	assert.Equal(t, inventory.TransportStdio, item.MCPServer.Transport)
	assert.Equal(t, "npx", item.MCPServer.Command)
	assert.Equal(t, []string{"-y", "@anthropic/mcp"}, item.MCPServer.Args)
	assert.Equal(t, []string{"ANTHROPIC_API_KEY"}, item.MCPServer.EnvVarNames)
	assert.Equal(t, []string{"read"}, item.MCPServer.AllowedTools)
	assert.Equal(t, []string{"file://*"}, item.MCPServer.AllowedResources)

	// Agent detail must not leak across kinds.
	assert.Nil(t, item.Agent)

	// AppDisplay is preserved as metadata so LocalSink can render it.
	assert.Equal(t, "Claude Code", item.Metadata[metaKeyAppDisplay])
}

func TestTranslateMCPServerSliceCopiedNotAliased(t *testing.T) {
	args := []string{"first"}
	tool := &aitool.AITool{
		Name:       "srv",
		Type:       aitool.AIToolTypeMCPServer,
		Scope:      aitool.AIToolScopeSystem,
		App:        "cursor",
		ConfigPath: "/x",
		MCPServer: &aitool.MCPServerConfig{
			Transport: aitool.MCPTransportStdio,
			Args:      args,
		},
	}

	item := translate(tool)
	args[0] = "mutated"

	require.NotNil(t, item.MCPServer)
	assert.Equal(t, "first", item.MCPServer.Args[0],
		"expected translate to deep-copy the args slice")
}

func TestTranslateCodingAgent(t *testing.T) {
	tool := &aitool.AITool{
		Name:       "claude-code",
		Type:       aitool.AIToolTypeCodingAgent,
		Scope:      aitool.AIToolScopeSystem,
		App:        "claude_code",
		ConfigPath: "/usr/local/bin/claude",
		Agent: &aitool.AgentConfig{
			Version:          "1.2.3",
			PermissionMode:   "ask",
			InstructionFiles: []string{"CLAUDE.md"},
			Model:            "claude-sonnet-4",
			APIKeyEnvName:    "ANTHROPIC_API_KEY",
		},
	}

	item := translate(tool)
	require.NotNil(t, item)
	assert.Equal(t, inventory.KindCodingAgent, item.Kind)
	require.NotNil(t, item.Agent)
	assert.Equal(t, "1.2.3", item.Agent.Version)
	assert.Equal(t, "ask", item.Agent.PermissionMode)
	assert.Equal(t, []string{"CLAUDE.md"}, item.Agent.InstructionFiles)
	assert.Equal(t, "claude-sonnet-4", item.Agent.Model)
	assert.Equal(t, "ANTHROPIC_API_KEY", item.Agent.APIKeyEnvName)
	assert.Nil(t, item.MCPServer)
}

func TestTranslateCLIToolStoresBinaryMetadata(t *testing.T) {
	tool := &aitool.AITool{
		Name:       "claude",
		Type:       aitool.AIToolTypeCLITool,
		Scope:      aitool.AIToolScopeSystem,
		App:        "claude_code",
		ConfigPath: "/usr/local/bin/claude",
		Metadata: map[string]any{
			metaKeyBinaryPath:    "/usr/local/bin/claude",
			metaKeyBinaryVersion: "1.2.3",
		},
	}

	item := translate(tool)
	require.NotNil(t, item)
	assert.Equal(t, inventory.KindCLITool, item.Kind)
	assert.Equal(t, "/usr/local/bin/claude", item.Metadata[metaKeyBinaryPath])
	assert.Equal(t, "1.2.3", item.Metadata[metaKeyBinaryVersion])
	assert.Nil(t, item.MCPServer)
	assert.Nil(t, item.Agent)
}

func TestTranslateAIExtensionStoresExtensionMetadata(t *testing.T) {
	tool := &aitool.AITool{
		Name:       "GitHub Copilot",
		Type:       aitool.AIToolTypeAIExtension,
		Scope:      aitool.AIToolScopeSystem,
		App:        "vscode",
		AppDisplay: "VS Code",
		ConfigPath: "/home/u/.vscode/extensions/github.copilot",
		Metadata: map[string]any{
			metaKeyExtensionID:      "github.copilot",
			metaKeyExtensionVersion: "1.234",
			metaKeyExtensionIDE:     "VS Code",
		},
	}

	item := translate(tool)
	require.NotNil(t, item)
	assert.Equal(t, inventory.KindAIExtension, item.Kind)
	assert.Equal(t, "github.copilot", item.Metadata[metaKeyExtensionID])
	assert.Equal(t, "1.234", item.Metadata[metaKeyExtensionVersion])
	assert.Equal(t, "VS Code", item.Metadata[metaKeyExtensionIDE])
	assert.Equal(t, "VS Code", item.Metadata[metaKeyAppDisplay])
}

func TestTranslateProjectConfig(t *testing.T) {
	tool := &aitool.AITool{
		Name:       "CLAUDE.md",
		Type:       aitool.AIToolTypeProjectConfig,
		Scope:      aitool.AIToolScopeProject,
		App:        "claude_code",
		ConfigPath: "/work/repo/CLAUDE.md",
		Agent: &aitool.AgentConfig{
			InstructionFiles: []string{"/work/repo/CLAUDE.md"},
		},
	}

	item := translate(tool)
	require.NotNil(t, item)
	assert.Equal(t, inventory.KindProjectConfig, item.Kind)
	require.NotNil(t, item.Agent,
		"ProjectConfig items carry Agent.InstructionFiles and the LocalSink renders them")
	assert.Equal(t, []string{"/work/repo/CLAUDE.md"}, item.Agent.InstructionFiles)
}

func TestTranslateIDEExtensionStoresExtensionMetadata(t *testing.T) {
	tool := &aitool.AITool{
		Name:       "ms-python.python",
		Type:       aitool.AIToolTypeIDEExtension,
		Scope:      aitool.AIToolScopeSystem,
		App:        "ide_extension",
		AppDisplay: "VS Code",
		ConfigPath: "/home/u/.vscode/extensions/extensions.json",
		Metadata: map[string]any{
			metaKeyExtensionID:      "ms-python.python",
			metaKeyExtensionVersion: "2024.1.0",
			metaKeyExtensionIDE:     "VS Code",
		},
	}

	item := translate(tool)
	require.NotNil(t, item)
	assert.Equal(t, inventory.KindIDEExtension, item.Kind)
	assert.Equal(t, "ms-python.python", item.Metadata[metaKeyExtensionID])
	assert.Equal(t, "2024.1.0", item.Metadata[metaKeyExtensionVersion])
	assert.Equal(t, "VS Code", item.Metadata[metaKeyExtensionIDE])
	assert.Equal(t, "VS Code", item.Metadata[metaKeyAppDisplay])
}

func TestTranslateUnknownTypeDegradesToUnspecified(t *testing.T) {
	tool := &aitool.AITool{
		Name:       "weird",
		Type:       aitool.AIToolType("brand_new_thing"),
		Scope:      aitool.AIToolScope("brand_new_scope"),
		App:        "x",
		ConfigPath: "/y",
	}

	item := translate(tool)
	require.NotNil(t, item)
	assert.Equal(t, inventory.KindUnspecified, item.Kind)
	assert.Equal(t, inventory.ScopeUnspecified, item.Scope)
}

func TestTranslateTransportMapping(t *testing.T) {
	cases := map[aitool.MCPTransport]inventory.Transport{
		aitool.MCPTransportStdio:          inventory.TransportStdio,
		aitool.MCPTransportSSE:            inventory.TransportSSE,
		aitool.MCPTransportStreamableHTTP: inventory.TransportStreamableHTTP,
		aitool.MCPTransport("unknown"):    inventory.TransportUnspecified,
	}
	for in, want := range cases {
		assert.Equal(t, want, translateTransport(in), "transport %q", in)
	}
}

func TestTranslateCopiesIdentityFromAITool(t *testing.T) {
	tool := &aitool.AITool{
		Type:       aitool.AIToolTypeMCPServer,
		Scope:      aitool.AIToolScopeProject,
		App:        "claude_code",
		Name:       "anthropic-mcp",
		ConfigPath: "/work/.mcp.json",
		ID:         "fixture-id",
		SourceID:   "fixture-source",
	}
	item := translate(tool)
	require.NotNil(t, item)
	assert.Equal(t, "fixture-id", item.ItemIdentity)
	assert.Equal(t, "fixture-source", item.SourceID)
}

func TestStringifyMetaValue(t *testing.T) {
	assert.Equal(t, "hello", stringifyMetaValue("hello"))
	assert.Equal(t, "42", stringifyMetaValue(42))
	assert.Equal(t, "true", stringifyMetaValue(true))
}

func TestBuildMetadataReturnsNilWhenEmpty(t *testing.T) {
	assert.Nil(t, buildMetadata(&aitool.AITool{}))
}

func TestCopyBoolPtrIndependent(t *testing.T) {
	original := true
	got := copyBoolPtr(&original)
	require.NotNil(t, got)
	assert.True(t, *got)
	original = false
	assert.True(t, *got, "copyBoolPtr must produce an independent pointer")
	assert.Nil(t, copyBoolPtr(nil))
}
