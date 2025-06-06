package server

import (
	"github.com/mark3labs/mcp-go/server"
	"github.com/safedep/vet/mcp"
)

type McpServerConfig struct {
	Name         string
	Version      string
	Instructions string

	SseServerBasePath string
	SseServerAddr     string
}

func DefaultMcpServerConfig() McpServerConfig {
	return McpServerConfig{
		Name:    "vet-mcp",
		Version: "0.0.1",
		Instructions: "This is a Model Context Protocol (MCP) server that vets open source dependencies for security issues." +
			"Always use the available tools to vet an open source dependency before using in AI generated code.",

		// SSE server will automatically add `/sse` to the base path
		SseServerBasePath: "",
		SseServerAddr:     "localhost:9988",
	}
}

// McpServer is the interface for a MCP server
type McpServer interface {
	RegisterTool(tool mcp.McpTool) error
	Start() error
	Stop() error
}

type mcpServer struct {
	config      McpServerConfig
	server      *server.MCPServer
	servingFunc func(*mcpServer) error
}

func newServer(config McpServerConfig) *server.MCPServer {
	return server.NewMCPServer(config.Name, config.Version,
		server.WithInstructions(config.Instructions),
		server.WithLogging())
}

// RegisterTool registers a tool with the MCP server
func (s *mcpServer) RegisterTool(tool mcp.McpTool) error {
	return tool.Register(s.server)
}

// Start the MCP server on the configured transport
func (s *mcpServer) Start() error {
	return s.servingFunc(s)
}

// Stop the MCP server
func (s *mcpServer) Stop() error {
	return nil
}
