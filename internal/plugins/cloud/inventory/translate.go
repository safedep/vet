package inventory

import (
	controltowerv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// event is a vet event and the user whose home directory holds its item.
type event struct {
	vet  *controltowerv1pb.VetInventoryEvent
	user *report.InventoryUser
}

// events maps an audit to its events: one for each item, the summary, then
// one for each diagnostic of the audit. A record of a scan that is not an
// endpoint scan has no type, so the syncer does not send it.
func events(a Audit) []event {
	out := make([]event, 0, len(a.Items)+1+len(a.Diagnostics))
	counts := map[string]uint32{}
	for i := range a.Items {
		it := &a.Items[i]
		kind, ok := kinds[it.Type]
		if !ok {
			log.Debugf("inventory sync: skip %s %q with no type", it.Kind, it.Name)
			continue
		}
		counts[kind.String()]++
		out = append(out, event{vet: controltowerv1pb.VetInventoryEvent_builder{
			EventType:    controltowerv1pb.VetInventoryEventType_VET_INVENTORY_EVENT_TYPE_ITEM_OBSERVED,
			ItemObserved: itemOf(it, kind),
		}.Build(), user: it.User})
	}
	var total uint32
	for _, n := range counts {
		total += n
	}
	out = append(out, event{vet: controltowerv1pb.VetInventoryEvent_builder{
		EventType: controltowerv1pb.VetInventoryEventType_VET_INVENTORY_EVENT_TYPE_SCAN_SUMMARY,
		ScanSummary: controltowerv1pb.VetInventoryEvent_ScanSummary_builder{
			TotalObserved: total, Completed: true, ErrorsCount: uint32(len(a.Diagnostics)), PerKindCounts: counts,
		}.Build(),
	}.Build()})
	for _, d := range a.Diagnostics {
		out = append(out, event{vet: controltowerv1pb.VetInventoryEvent_builder{
			EventType: controltowerv1pb.VetInventoryEventType_VET_INVENTORY_EVENT_TYPE_ERROR,
			Error: controltowerv1pb.VetInventoryEvent_ScanError_builder{
				Discoverer: d.Component, ErrorType: d.Code, Message: d.Message,
			}.Build(),
		}.Build()})
	}
	return out
}

var kinds = map[report.InventoryType]controltowerv1pb.InventoryItemKind{
	report.InventoryTypeMCPServer:        controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_MCP_SERVER,
	report.InventoryTypeCodingAgent:      controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_CODING_AGENT,
	report.InventoryTypeAIExtension:      controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_AI_EXTENSION,
	report.InventoryTypeCLITool:          controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_CLI_TOOL,
	report.InventoryTypeProjectConfig:    controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_PROJECT_CONFIG,
	report.InventoryTypeBrowserExtension: controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_BROWSER_EXTENSION,
	report.InventoryTypeIDEExtension:     controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_IDE_EXTENSION,
	report.InventoryTypeAgentPlugin:      controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_AGENT_PLUGIN,
	report.InventoryTypeSkill:            controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_AGENT_SKILL,
}

func itemOf(it *report.InventoryItem, kind controltowerv1pb.InventoryItemKind) *controltowerv1pb.VetInventoryEvent_ItemObserved {
	b := controltowerv1pb.VetInventoryEvent_ItemObserved_builder{
		Kind: kind, ItemIdentity: it.Identity, SourceId: it.Source, Name: it.Name, App: it.Client,
		Scope: scopeOf(it.Scope), ConfigPath: it.Path, Enabled: it.Enabled, Metadata: it.Details,
	}
	// Control-tower rejects an event whose kind has no detail of its own,
	// and an event with the detail of another kind.
	switch kind {
	case controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_MCP_SERVER:
		b.McpServer = mcpOf(it.MCPServer)
	case controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_CODING_AGENT:
		b.Agent = agentOf(it)
	case controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_IDE_EXTENSION, controltowerv1pb.InventoryItemKind_INVENTORY_ITEM_KIND_AI_EXTENSION:
		b.IdeExtension = extensionOf(it)
	}
	return b.Build()
}

func scopeOf(s string) controltowerv1pb.InventoryScope {
	switch s {
	case "system":
		return controltowerv1pb.InventoryScope_INVENTORY_SCOPE_SYSTEM
	case "project":
		return controltowerv1pb.InventoryScope_INVENTORY_SCOPE_PROJECT
	}
	return controltowerv1pb.InventoryScope_INVENTORY_SCOPE_UNSPECIFIED
}

var transports = map[string]controltowerv1pb.VetInventoryEvent_MCPServerDetail_Transport{
	"stdio":           controltowerv1pb.VetInventoryEvent_MCPServerDetail_TRANSPORT_STDIO,
	"sse":             controltowerv1pb.VetInventoryEvent_MCPServerDetail_TRANSPORT_SSE,
	"streamable_http": controltowerv1pb.VetInventoryEvent_MCPServerDetail_TRANSPORT_STREAMABLE_HTTP,
}

func mcpOf(m *report.InventoryMCP) *controltowerv1pb.VetInventoryEvent_MCPServerDetail {
	if m == nil {
		return controltowerv1pb.VetInventoryEvent_MCPServerDetail_builder{}.Build()
	}
	return controltowerv1pb.VetInventoryEvent_MCPServerDetail_builder{
		Transport: transports[m.Transport], Command: m.Command, Args: m.Args, Url: m.URL,
		EnvVarNames: m.EnvNames, HeaderNames: m.HeaderNames,
		AllowedTools: m.AllowedTools, AllowedResources: m.AllowedResources,
	}.Build()
}

func agentOf(it *report.InventoryItem) *controltowerv1pb.VetInventoryEvent_AgentDetail {
	b := controltowerv1pb.VetInventoryEvent_AgentDetail_builder{Version: it.Version}
	if a := it.Agent; a != nil {
		b.PermissionMode, b.Model, b.InstructionFiles, b.ApiKeyEnvName = a.PermissionMode, a.Model, a.InstructionFiles, a.APIKeyEnvName
	}
	return b.Build()
}

func extensionOf(it *report.InventoryItem) *controltowerv1pb.VetInventoryEvent_IDEExtensionDetail {
	e := it.Extension
	if e == nil {
		return controltowerv1pb.VetInventoryEvent_IDEExtensionDetail_builder{}.Build()
	}
	return controltowerv1pb.VetInventoryEvent_IDEExtensionDetail_builder{
		Ide: e.IDE, PackageVersion: packageOf(e, it.Version),
	}.Build()
}

// packageOf returns the registry package of an extension, or nil when no
// marketplace serves it.
func packageOf(e *report.InventoryExtension, version string) *packagev1.PackageVersion {
	if e.Package == "" || version == "" || !e.Ecosystem.Valid() {
		return nil
	}
	pv, err := model.NewPackageVersion(e.Ecosystem, e.Package, version)
	if err != nil {
		log.Debugf("inventory sync: extension %s: %v", e.Package, err)
		return nil
	}
	return pv.RawProto()
}

func invocationContext(u *report.InventoryUser) *controltowerv1pb.EndpointInvocationContext {
	return controltowerv1pb.EndpointInvocationContext_builder{Username: u.Name, UsernameUid: u.UID}.Build()
}
