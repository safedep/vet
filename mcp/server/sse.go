package server

import (
	"net/http"

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

			customSrv := http.Server{
				Addr:           config.SseServerAddr,
				MaxHeaderBytes: 1 << 20,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodHead {
						w.WriteHeader(http.StatusOK)
						return
					}

					s.ServeHTTP(w, r)
				}),
			}

			return customSrv.ListenAndServe()
		},
	}, nil
}
