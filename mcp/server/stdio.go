package server

import (
	"github.com/mark3labs/mcp-go/server"
	"github.com/safedep/vet/pkg/common/logger"
)

func NewMcpServerWithStdioTransport(config McpServerConfig) (*mcpServer, error) {
	srv := newServer(config)
	return &mcpServer{
		config: config,
		server: srv,
		servingFunc: func(srv *mcpServer) error {
			logger.Infof("Starting MCP server with stdio transport")
			return server.ServeStdio(srv.server)
		},
	}, nil
}
