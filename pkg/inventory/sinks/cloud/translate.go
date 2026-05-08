// Package cloud implements an inventory.Sink that ships discovered
// items, the end-of-scan summary, and per-discoverer errors to
// SafeDep Cloud via the endpointsync WAL. Translation between the
// in-process inventory.Item domain type and the wire proto lives in
// this package; the orchestrator never sees proto types.
package cloud

import (
	controltowerv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"

	"github.com/safedep/vet/pkg/inventory"
)

// itemToVetEvent wraps a single inventory item in a VetInventoryEvent
// with event_type = ITEM_OBSERVED and the item_observed payload set.
func itemToVetEvent(item *inventory.Item) *controltowerv1pb.VetInventoryEvent {
	return controltowerv1pb.VetInventoryEvent_builder{
		EventType:    controltowerv1pb.VetInventoryEventType_VET_INVENTORY_EVENT_TYPE_ITEM_OBSERVED,
		ItemObserved: inventoryItemToProto(item),
	}.Build()
}

// summaryToVetEvent wraps a scan summary in a VetInventoryEvent with
// event_type = SCAN_SUMMARY. completed=true because the orchestrator
// only invokes Sink.End on a normal completion path.
func summaryToVetEvent(summary *inventory.ScanSummary) *controltowerv1pb.VetInventoryEvent {
	return controltowerv1pb.VetInventoryEvent_builder{
		EventType:   controltowerv1pb.VetInventoryEventType_VET_INVENTORY_EVENT_TYPE_SCAN_SUMMARY,
		ScanSummary: scanSummaryToProto(summary),
	}.Build()
}

// scanErrorToVetEvent wraps a single discoverer-level error in a
// VetInventoryEvent with event_type = ERROR.
func scanErrorToVetEvent(e inventory.ScanError) *controltowerv1pb.VetInventoryEvent {
	return controltowerv1pb.VetInventoryEvent_builder{
		EventType: controltowerv1pb.VetInventoryEventType_VET_INVENTORY_EVENT_TYPE_ERROR,
		Error: controltowerv1pb.VetInventoryEvent_ScanError_builder{
			Discoverer: e.ScannerName,
			ErrorType:  e.ErrorType,
			Message:    e.Message,
		}.Build(),
	}.Build()
}

// inventoryItemToProto translates an *inventory.Item 1:1 to its proto
// counterpart. Pointer fields (Enabled, MCPServer, Agent) preserve
// optional semantics: nil means "not set" on the wire.
func inventoryItemToProto(item *inventory.Item) *controltowerv1pb.VetInventoryEvent_ItemObserved {
	return controltowerv1pb.VetInventoryEvent_ItemObserved_builder{
		Kind:         controltowerv1pb.InventoryItemKind(item.Kind),
		ItemIdentity: item.ItemIdentity,
		SourceId:     item.SourceID,
		Name:         item.Name,
		App:          item.App,
		Scope:        controltowerv1pb.InventoryScope(item.Scope),
		ConfigPath:   item.ConfigPath,
		Enabled:      item.Enabled,
		McpServer:    mcpDetailToProto(item.MCPServer),
		Agent:        agentDetailToProto(item.Agent),
		Metadata:     item.Metadata,
	}.Build()
}

// mcpDetailToProto converts MCP-server details. Returns nil when the
// source detail is nil so the proto's optional field stays unset.
func mcpDetailToProto(d *inventory.MCPServerDetail) *controltowerv1pb.VetInventoryEvent_MCPServerDetail {
	if d == nil {
		return nil
	}
	return controltowerv1pb.VetInventoryEvent_MCPServerDetail_builder{
		Transport:        controltowerv1pb.VetInventoryEvent_MCPServerDetail_Transport(d.Transport),
		Command:          d.Command,
		Args:             d.Args,
		Url:              d.URL,
		EnvVarNames:      d.EnvVarNames,
		HeaderNames:      d.HeaderNames,
		AllowedTools:     d.AllowedTools,
		AllowedResources: d.AllowedResources,
	}.Build()
}

// agentDetailToProto converts coding-agent details. Returns nil when
// the source detail is nil.
func agentDetailToProto(d *inventory.AgentDetail) *controltowerv1pb.VetInventoryEvent_AgentDetail {
	if d == nil {
		return nil
	}
	return controltowerv1pb.VetInventoryEvent_AgentDetail_builder{
		Version:          d.Version,
		PermissionMode:   d.PermissionMode,
		InstructionFiles: d.InstructionFiles,
		Model:            d.Model,
		ApiKeyEnvName:    d.APIKeyEnvName,
	}.Build()
}

// scanSummaryToProto translates a *inventory.ScanSummary to the proto
// ScanSummary sub-message. PerKindCounts is keyed by the proto enum's
// canonical name (e.g. "INVENTORY_ITEM_KIND_MCP_SERVER"); we delegate
// to InventoryItemKind.String() so the keys stay in lockstep with the
// generated enum.
//
// TotalObserved narrows from uint64 (domain) to uint32 (wire). The
// inventory pipeline produces counts in the millions worst-case, well
// below 2^32, so the narrower wire type is safe; the cast is documented
// here rather than asserted, matching the proto contract.
func scanSummaryToProto(s *inventory.ScanSummary) *controltowerv1pb.VetInventoryEvent_ScanSummary {
	perKind := make(map[string]uint32, len(s.KindCounts))
	for k, v := range s.KindCounts {
		perKind[controltowerv1pb.InventoryItemKind(k).String()] = uint32(v)
	}
	return controltowerv1pb.VetInventoryEvent_ScanSummary_builder{
		TotalObserved: uint32(s.TotalObserved),
		Completed:     true,
		ErrorsCount:   uint32(len(s.Errors)),
		PerKindCounts: perKind,
	}.Build()
}
