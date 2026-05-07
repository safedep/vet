// Package aitool adapts the aitool discovery layer to the inventory
// producer pipeline. It translates aitool.AITool values emitted by the
// aitool registry into wire-decoupled inventory.Item values.
package aitool

import (
	"fmt"

	"github.com/safedep/vet/pkg/aitool"
	"github.com/safedep/vet/pkg/inventory"
)

// Metadata keys mirror the canonical names used elsewhere in vet (see
// pkg/aitool/cli_common.go and pkg/aitool/ai_extension.go).
const (
	metaKeyAppDisplay       = "app.display"
	metaKeyBinaryVersion    = "binary.version"
	metaKeyBinaryPath       = "binary.path"
	metaKeyExtensionID      = "extension.id"
	metaKeyExtensionVersion = "extension.version"
	metaKeyExtensionIDE     = "extension.ide"
)

// translate converts an aitool.AITool to a wire-decoupled inventory.Item.
// Pure function: no I/O, no globals, deterministic.
func translate(t *aitool.AITool) *inventory.Item {
	if t == nil {
		return nil
	}

	kind := translateKind(t.Type)
	scope := translateScope(t.Scope)

	item := &inventory.Item{
		Kind:         kind,
		ItemIdentity: t.ID,
		SourceID:     t.SourceID,
		Name:         t.Name,
		App:          t.App,
		Scope:        scope,
		ConfigPath:   t.ConfigPath,
		Enabled:      copyBoolPtr(t.Enabled),
	}

	if t.Type == aitool.AIToolTypeMCPServer && t.MCPServer != nil {
		item.MCPServer = translateMCPServer(t.MCPServer)
	}
	if t.Type == aitool.AIToolTypeCodingAgent && t.Agent != nil {
		item.Agent = translateAgent(t.Agent)
	}

	item.Metadata = buildMetadata(t)
	return item
}

// translateKind maps aitool.AIToolType to inventory.Kind. Unknown types
// collapse to KindUnspecified — the caller is free to drop these.
func translateKind(t aitool.AIToolType) inventory.Kind {
	switch t {
	case aitool.AIToolTypeMCPServer:
		return inventory.KindMCPServer
	case aitool.AIToolTypeCodingAgent:
		return inventory.KindCodingAgent
	case aitool.AIToolTypeAIExtension:
		return inventory.KindAIExtension
	case aitool.AIToolTypeCLITool:
		return inventory.KindCLITool
	case aitool.AIToolTypeProjectConfig:
		return inventory.KindProjectConfig
	default:
		return inventory.KindUnspecified
	}
}

// translateScope maps aitool.AIToolScope to inventory.Scope.
func translateScope(s aitool.AIToolScope) inventory.Scope {
	switch s {
	case aitool.AIToolScopeSystem:
		return inventory.ScopeSystem
	case aitool.AIToolScopeProject:
		return inventory.ScopeProject
	default:
		return inventory.ScopeUnspecified
	}
}

// translateTransport maps aitool's MCP transport string enum to the
// inventory transport enum.
func translateTransport(t aitool.MCPTransport) inventory.Transport {
	switch t {
	case aitool.MCPTransportStdio:
		return inventory.TransportStdio
	case aitool.MCPTransportSSE:
		return inventory.TransportSSE
	case aitool.MCPTransportStreamableHTTP:
		return inventory.TransportStreamableHTTP
	default:
		return inventory.TransportUnspecified
	}
}

// translateMCPServer converts the aitool MCP server config to the typed
// inventory detail. Slices are copied to avoid aliasing the source.
func translateMCPServer(s *aitool.MCPServerConfig) *inventory.MCPServerDetail {
	return &inventory.MCPServerDetail{
		Transport:        translateTransport(s.Transport),
		Command:          s.Command,
		Args:             cloneStrings(s.Args),
		URL:              s.URL,
		EnvVarNames:      cloneStrings(s.EnvVarNames),
		HeaderNames:      cloneStrings(s.HeaderNames),
		AllowedTools:     cloneStrings(s.AllowedTools),
		AllowedResources: cloneStrings(s.AllowedResources),
	}
}

// translateAgent converts the aitool agent config to the typed inventory
// detail. Slices are copied to avoid aliasing the source.
func translateAgent(a *aitool.AgentConfig) *inventory.AgentDetail {
	return &inventory.AgentDetail{
		Version:          a.Version,
		PermissionMode:   a.PermissionMode,
		InstructionFiles: cloneStrings(a.InstructionFiles),
		Model:            a.Model,
		APIKeyEnvName:    a.APIKeyEnvName,
	}
}

// buildMetadata flattens aitool's free-form map[string]any plus the
// AppDisplay convenience field into the inventory.Item metadata
// (map[string]string). Non-string values are formatted with %v.
//
// Returns nil when no metadata would be emitted, to keep the inventory
// item tidy in the empty case.
func buildMetadata(t *aitool.AITool) map[string]string {
	if t.AppDisplay == "" && len(t.Metadata) == 0 {
		return nil
	}

	out := make(map[string]string, len(t.Metadata)+1)
	if t.AppDisplay != "" {
		out[metaKeyAppDisplay] = t.AppDisplay
	}
	for k, v := range t.Metadata {
		out[k] = stringifyMetaValue(v)
	}
	return out
}

// stringifyMetaValue converts a metadata value to its string
// representation. Strings pass through; everything else uses %v so the
// metadata map remains string-valued.
func stringifyMetaValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func copyBoolPtr(b *bool) *bool {
	if b == nil {
		return nil
	}
	v := *b
	return &v
}
