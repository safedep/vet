package server

import (
	"github.com/mark3labs/mcp-go/server"
	"github.com/safedep/vet/pkg/common/logger"
)

func NewMcpServerWithSseTransport(config McpServerConfig) (*mcpServer, error) {
	srv := newServer(config)
	return &mcpServer{
		config: config,
		server: srv,
		servingFunc: func(srv *mcpServer) error {
			logger.Infof("Starting MCP server with SSE transport: %s", config.SseServerAddr)
			s := server.NewSSEServer(srv.server, server.WithStaticBasePath(config.SseServerBasePath))
			return s.Start(config.SseServerAddr)
		},
	}, nil
}
