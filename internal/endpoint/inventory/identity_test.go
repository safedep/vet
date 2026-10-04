package inventory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestItemIdentityPinned(t *testing.T) {
	assert.Equal(t, "1fccf1273361f494", ItemIdentity("claude_code", KindMCPServer, ScopeProject, "safedep", "/p/.mcp.json"))
}

func TestItemIdentityChangesWithEachField(t *testing.T) {
	base := ItemIdentity("claude_code", KindMCPServer, ScopeProject, "safedep", "/p/.mcp.json")
	tests := []struct {
		name string
		got  string
	}{
		{"app", ItemIdentity("cursor", KindMCPServer, ScopeProject, "safedep", "/p/.mcp.json")},
		{"kind", ItemIdentity("claude_code", KindCodingAgent, ScopeProject, "safedep", "/p/.mcp.json")},
		{"scope", ItemIdentity("claude_code", KindMCPServer, ScopeSystem, "safedep", "/p/.mcp.json")},
		{"name", ItemIdentity("claude_code", KindMCPServer, ScopeProject, "other", "/p/.mcp.json")},
		{"config path", ItemIdentity("claude_code", KindMCPServer, ScopeProject, "safedep", "/q/.mcp.json")},
		{"case", ItemIdentity("claude_code", KindMCPServer, ScopeProject, "SafeDep", "/p/.mcp.json")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEqual(t, base, tt.got)
		})
	}
}

func TestSourceID(t *testing.T) {
	assert.Equal(t, "39ff8fef0834f2b", SourceID("claude_code", "/p/.mcp.json"))
	assert.NotEqual(t, SourceID("claude_code", "/p/.mcp.json"), SourceID("claude_code", "/q/.mcp.json"))
	assert.NotEqual(t, SourceID("claude_code", "/p/.mcp.json"), SourceID("cursor", "/p/.mcp.json"))
}
