package cloud

import (
	"testing"

	controltowerv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/pkg/inventory"
)

func TestItemToVetEvent_PlainItem(t *testing.T) {
	item := &inventory.Item{
		Kind:         inventory.KindCLITool,
		ItemIdentity: "id-1",
		SourceID:     "src-1",
		Name:         "claude",
		App:          "claude_code",
		Scope:        inventory.ScopeSystem,
		ConfigPath:   "/usr/local/bin/claude",
		Metadata: map[string]string{
			"binary.path":    "/usr/local/bin/claude",
			"binary.version": "1.2.3",
		},
	}

	ev := itemToVetEvent(item)

	require.NotNil(t, ev)
	assert.Equal(t,
		controltowerv1pb.VetInventoryEventType_VET_INVENTORY_EVENT_TYPE_ITEM_OBSERVED,
		ev.GetEventType())
	require.True(t, ev.HasItemObserved())
	assert.False(t, ev.HasScanSummary())
	assert.False(t, ev.HasError())

	io := ev.GetItemObserved()
	assert.Equal(t,
		controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_CLI_TOOL,
		io.GetKind())
	assert.Equal(t, "id-1", io.GetItemIdentity())
	assert.Equal(t, "src-1", io.GetSourceId())
	assert.Equal(t, "claude", io.GetName())
	assert.Equal(t, "claude_code", io.GetApp())
	assert.Equal(t,
		controltowerv1pb.InventoryScope_INVENTORY_SCOPE_SYSTEM,
		io.GetScope())
	assert.Equal(t, "/usr/local/bin/claude", io.GetConfigPath())
	assert.False(t, io.HasEnabled())
	assert.False(t, io.HasMcpServer())
	assert.False(t, io.HasAgent())
	assert.Equal(t, item.Metadata, io.GetMetadata())
}

func TestItemToVetEvent_WithMCPServerDetail(t *testing.T) {
	enabled := true
	item := &inventory.Item{
		Kind:         inventory.KindMCPServer,
		ItemIdentity: "id-mcp",
		Name:         "anthropic-mcp",
		App:          "claude_code",
		Scope:        inventory.ScopeProject,
		ConfigPath:   "/work/.mcp.json",
		Enabled:      &enabled,
		MCPServer: &inventory.MCPServerDetail{
			Transport:        inventory.TransportStdio,
			Command:          "npx",
			Args:             []string{"-y", "@anthropic/mcp"},
			URL:              "",
			EnvVarNames:      []string{"ANTHROPIC_API_KEY"},
			HeaderNames:      []string{"X-Auth"},
			AllowedTools:     []string{"read_file"},
			AllowedResources: []string{"file://**"},
		},
	}

	ev := itemToVetEvent(item)

	io := ev.GetItemObserved()
	require.True(t, io.HasMcpServer())
	require.True(t, io.HasEnabled())
	assert.True(t, io.GetEnabled())
	assert.False(t, io.HasAgent())

	mcp := io.GetMcpServer()
	assert.Equal(t,
		controltowerv1pb.VetInventoryEvent_MCPServerDetail_TRANSPORT_STDIO,
		mcp.GetTransport())
	assert.Equal(t, "npx", mcp.GetCommand())
	assert.Equal(t, []string{"-y", "@anthropic/mcp"}, mcp.GetArgs())
	assert.Equal(t, "", mcp.GetUrl())
	assert.Equal(t, []string{"ANTHROPIC_API_KEY"}, mcp.GetEnvVarNames())
	assert.Equal(t, []string{"X-Auth"}, mcp.GetHeaderNames())
	assert.Equal(t, []string{"read_file"}, mcp.GetAllowedTools())
	assert.Equal(t, []string{"file://**"}, mcp.GetAllowedResources())
}

func TestItemToVetEvent_WithAgentDetail(t *testing.T) {
	disabled := false
	item := &inventory.Item{
		Kind:         inventory.KindCodingAgent,
		ItemIdentity: "id-agent",
		Name:         "claude-code",
		App:          "claude_code",
		Scope:        inventory.ScopeSystem,
		Enabled:      &disabled,
		Agent: &inventory.AgentDetail{
			Version:          "0.4.0",
			PermissionMode:   "ask",
			InstructionFiles: []string{"/work/CLAUDE.md"},
			Model:            "claude-opus-4-7",
			APIKeyEnvName:    "ANTHROPIC_API_KEY",
		},
	}

	ev := itemToVetEvent(item)

	io := ev.GetItemObserved()
	require.True(t, io.HasAgent())
	require.True(t, io.HasEnabled())
	assert.False(t, io.GetEnabled())
	assert.False(t, io.HasMcpServer())

	agent := io.GetAgent()
	assert.Equal(t, "0.4.0", agent.GetVersion())
	assert.Equal(t, "ask", agent.GetPermissionMode())
	assert.Equal(t, []string{"/work/CLAUDE.md"}, agent.GetInstructionFiles())
	assert.Equal(t, "claude-opus-4-7", agent.GetModel())
	assert.Equal(t, "ANTHROPIC_API_KEY", agent.GetApiKeyEnvName())
}

func TestSummaryToVetEvent(t *testing.T) {
	summary := &inventory.ScanSummary{
		TotalObserved: 5,
		KindCounts: map[inventory.Kind]uint64{
			inventory.KindMCPServer: 3,
			inventory.KindCLITool:   2,
		},
		Errors: []inventory.ScanError{
			{ScannerName: "x", ErrorType: "scanner_failed", Message: "boom"},
		},
	}

	ev := summaryToVetEvent(summary)

	require.NotNil(t, ev)
	assert.Equal(t,
		controltowerv1pb.VetInventoryEventType_VET_INVENTORY_EVENT_TYPE_SCAN_SUMMARY,
		ev.GetEventType())
	require.True(t, ev.HasScanSummary())
	assert.False(t, ev.HasItemObserved())
	assert.False(t, ev.HasError())

	s := ev.GetScanSummary()
	assert.Equal(t, uint32(5), s.GetTotalObserved())
	assert.Equal(t, uint32(1), s.GetErrorsCount())
	assert.True(t, s.GetCompleted())

	pkc := s.GetPerKindCounts()
	assert.Equal(t, uint32(3), pkc["INVENTORY_ITEM_KIND_MCP_SERVER"])
	assert.Equal(t, uint32(2), pkc["INVENTORY_ITEM_KIND_CLI_TOOL"])
	assert.Len(t, pkc, 2)
}

func TestScanErrorToVetEvent(t *testing.T) {
	e := inventory.ScanError{
		ScannerName: "aitool",
		ErrorType:   "scanner_failed",
		Message:     "permission denied",
	}

	ev := scanErrorToVetEvent(e)

	require.NotNil(t, ev)
	assert.Equal(t,
		controltowerv1pb.VetInventoryEventType_VET_INVENTORY_EVENT_TYPE_ERROR,
		ev.GetEventType())
	require.True(t, ev.HasError())
	assert.False(t, ev.HasItemObserved())
	assert.False(t, ev.HasScanSummary())

	pe := ev.GetError()
	assert.Equal(t, "aitool", pe.GetDiscoverer())
	assert.Equal(t, "scanner_failed", pe.GetErrorType())
	assert.Equal(t, "permission denied", pe.GetMessage())
}

func TestMCPDetailToProto_NilReturnsNil(t *testing.T) {
	assert.Nil(t, mcpDetailToProto(nil))
}

func TestAgentDetailToProto_NilReturnsNil(t *testing.T) {
	assert.Nil(t, agentDetailToProto(nil))
}
