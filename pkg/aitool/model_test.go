package aitool

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_generateID_Deterministic(t *testing.T) {
	id1 := generateID("claude_code", "mcp_server", "project", "safedep", "/path/.mcp.json")
	id2 := generateID("claude_code", "mcp_server", "project", "safedep", "/path/.mcp.json")
	assert.Equal(t, id1, id2, "same inputs should produce same ID")
}

func Test_generateID_CaseInsensitive(t *testing.T) {
	id1 := generateID("Claude_Code", "MCP_Server", "Project", "SafeDep", "/Path/.mcp.json")
	id2 := generateID("claude_code", "mcp_server", "project", "safedep", "/path/.mcp.json")
	assert.Equal(t, id1, id2, "IDs should be case-insensitive")
}

func Test_generateID_DifferentInputs(t *testing.T) {
	id1 := generateID("claude_code", "mcp_server", "project", "safedep", "/path/.mcp.json")
	id2 := generateID("cursor", "mcp_server", "project", "safedep", "/path/.mcp.json")
	assert.NotEqual(t, id1, id2, "different apps should produce different IDs")
}

func Test_generateSourceID_Deterministic(t *testing.T) {
	id1 := generateSourceID("claude_code", "/path/.mcp.json")
	id2 := generateSourceID("claude_code", "/path/.mcp.json")
	assert.Equal(t, id1, id2)
}

func Test_generateSourceID_SameAppDifferentPath(t *testing.T) {
	id1 := generateSourceID("claude_code", "/path/.mcp.json")
	id2 := generateSourceID("claude_code", "/other/.mcp.json")
	assert.NotEqual(t, id1, id2)
}

func TestAITool_Metadata(t *testing.T) {
	tool := &AITool{}

	// GetMeta on nil map returns nil
	assert.Nil(t, tool.GetMeta("key"))
	assert.Equal(t, "", tool.GetMetaString("key"))

	// SetMeta initializes the map
	tool.SetMeta("test.key", "value")
	assert.Equal(t, "value", tool.GetMeta("test.key"))
	assert.Equal(t, "value", tool.GetMetaString("test.key"))

	// Non-string metadata
	tool.SetMeta("test.bool", true)
	assert.Equal(t, true, tool.GetMeta("test.bool"))
	assert.Equal(t, "", tool.GetMetaString("test.bool"))
}

func TestAIToolInventory_Add(t *testing.T) {
	inv := NewAIToolInventory()
	tool := &AITool{Name: "test", Type: AIToolTypeMCPServer, App: "claude_code", Scope: AIToolScopeProject}
	inv.Add(tool)
	assert.Len(t, inv.Tools, 1)
}

func TestAIToolInventory_FilterByType(t *testing.T) {
	inv := NewAIToolInventory()
	inv.Add(&AITool{Name: "server1", Type: AIToolTypeMCPServer})
	inv.Add(&AITool{Name: "agent1", Type: AIToolTypeCodingAgent})
	inv.Add(&AITool{Name: "server2", Type: AIToolTypeMCPServer})

	servers := inv.FilterByType(AIToolTypeMCPServer)
	assert.Len(t, servers, 2)
	agents := inv.FilterByType(AIToolTypeCodingAgent)
	assert.Len(t, agents, 1)
}

func TestAIToolInventory_FilterByApp(t *testing.T) {
	inv := NewAIToolInventory()
	inv.Add(&AITool{Name: "tool1", App: "claude_code"})
	inv.Add(&AITool{Name: "tool2", App: "cursor"})
	inv.Add(&AITool{Name: "tool3", App: "claude_code"})

	result := inv.FilterByApp("claude_code")
	assert.Len(t, result, 2)
}

func TestAIToolInventory_FilterByScope(t *testing.T) {
	inv := NewAIToolInventory()
	inv.Add(&AITool{Name: "tool1", Scope: AIToolScopeSystem})
	inv.Add(&AITool{Name: "tool2", Scope: AIToolScopeProject})

	result := inv.FilterByScope(AIToolScopeSystem)
	assert.Len(t, result, 1)
	assert.Equal(t, "tool1", result[0].Name)
}

func TestAIToolInventory_FilterBySourceID(t *testing.T) {
	inv := NewAIToolInventory()
	inv.Add(&AITool{Name: "tool1", SourceID: "abc"})
	inv.Add(&AITool{Name: "tool2", SourceID: "def"})
	inv.Add(&AITool{Name: "tool3", SourceID: "abc"})

	result := inv.FilterBySourceID("abc")
	assert.Len(t, result, 2)
}

func TestAIToolInventory_GroupByApp(t *testing.T) {
	inv := NewAIToolInventory()
	inv.Add(&AITool{Name: "tool1", App: "claude_code"})
	inv.Add(&AITool{Name: "tool2", App: "cursor"})
	inv.Add(&AITool{Name: "tool3", App: "claude_code"})

	groups := inv.GroupByApp()
	assert.Len(t, groups, 2)
	assert.Len(t, groups["claude_code"], 2)
	assert.Len(t, groups["cursor"], 1)
}

func TestAIToolInventory_GroupBySourceID(t *testing.T) {
	inv := NewAIToolInventory()
	inv.Add(&AITool{Name: "tool1", SourceID: "src1"})
	inv.Add(&AITool{Name: "tool2", SourceID: "src2"})
	inv.Add(&AITool{Name: "tool3", SourceID: "src1"})

	groups := inv.GroupBySourceID()
	assert.Len(t, groups, 2)
	assert.Len(t, groups["src1"], 2)
}
