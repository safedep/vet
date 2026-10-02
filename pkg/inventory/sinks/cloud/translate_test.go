package cloud

import (
	"testing"

	controltowerv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/pkg/inventory"
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

func TestItemToVetEvent_WithIDEExtensionDetail(t *testing.T) {
	cases := []struct {
		name      string
		ecosystem string
		want      packagev1.Ecosystem
	}{
		{"vscode marketplace", "VSCodeExtensions", packagev1.Ecosystem_ECOSYSTEM_VSCODE},
		{"open vsx", "OpenVSXExtensions", packagev1.Ecosystem_ECOSYSTEM_OPENVSX},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			item := &inventory.Item{
				Kind:         inventory.KindIDEExtension,
				ItemIdentity: "id-ext",
				Name:         "ms-python.python",
				IDEExtension: &inventory.IDEExtensionDetail{
					Package: &inventory.PackageIdentity{
						Ecosystem: tc.ecosystem,
						Name:      "ms-python.python",
						Version:   "2024.1.0",
					},
					IDE: "VS Code",
				},
			}

			io := itemToVetEvent(item).GetItemObserved()
			require.True(t, io.HasIdeExtension())
			assert.False(t, io.HasMcpServer())
			assert.False(t, io.HasAgent())

			ext := io.GetIdeExtension()
			assert.Equal(t, "VS Code", ext.GetIde())
			require.True(t, ext.HasPackageVersion())
			pv := ext.GetPackageVersion()
			assert.Equal(t, tc.want, pv.GetPackage().GetEcosystem())
			assert.Equal(t, "ms-python.python", pv.GetPackage().GetName())
			assert.Equal(t, "2024.1.0", pv.GetVersion())
		})
	}
}

func TestItemToVetEvent_IncompletePackageIdentityKeepsDetailWithoutIt(t *testing.T) {
	cases := []struct {
		name string
		pkg  *inventory.PackageIdentity
	}{
		{"no identity", nil},
		{"unknown ecosystem", &inventory.PackageIdentity{Ecosystem: "npm-but-wrong", Name: "a.b", Version: "1.0.0"}},
		{"no name", &inventory.PackageIdentity{Ecosystem: "VSCodeExtensions", Version: "1.0.0"}},
		{"no version", &inventory.PackageIdentity{Ecosystem: "VSCodeExtensions", Name: "a.b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			item := &inventory.Item{
				Kind:         inventory.KindIDEExtension,
				ItemIdentity: "id-ext",
				Name:         "a.b",
				IDEExtension: &inventory.IDEExtensionDetail{Package: tc.pkg, IDE: "VS Code"},
			}

			io := itemToVetEvent(item).GetItemObserved()
			require.True(t, io.HasIdeExtension())
			assert.Equal(t, "VS Code", io.GetIdeExtension().GetIde())
			assert.False(t, io.GetIdeExtension().HasPackageVersion())
		})
	}
}

func TestIDEExtensionDetailToProto_NilReturnsNil(t *testing.T) {
	assert.Nil(t, ideExtensionDetailToProto(nil))
}

func TestPackageIdentityToProto_NilReturnsNil(t *testing.T) {
	assert.Nil(t, packageIdentityToProto(nil))
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
