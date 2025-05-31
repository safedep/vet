package mcp

import "github.com/mark3labs/mcp-go/server"

// Contract for implementing an MCP tool
type McpTool interface {
	// Function that should be implemented by the tools to register itself
	// with the MCP server.
	Register(server *server.MCPServer) error
}
