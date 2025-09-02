package server

import (
	"net/http"

	"github.com/mark3labs/mcp-go/server"
	"github.com/safedep/vet/pkg/common/logger"
)

// sseHandlerWithHeadSupport wraps the SSE handler to add support for HTTP HEAD requests.
// HEAD requests will return the same headers as GET requests but without a body,
// allowing tools like Langchain to probe the endpoint for health or capability checks.
func sseHandlerWithHeadSupport(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only handle HEAD requests to the SSE endpoint specifically
		if r.Method == http.MethodHead && r.URL.Path == "/sse" {
			// For HEAD requests to SSE endpoint, set the same headers as SSE connections but don't send a body
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(http.StatusOK)
			return
		}
		// For all other requests (including GET, and HEAD to other endpoints), delegate to the original handler
		handler.ServeHTTP(w, r)
	})
}

func NewMcpServerWithSseTransport(config McpServerConfig) (*mcpServer, error) {
	srv := newServer(config)
	return &mcpServer{
		config: config,
		server: srv,
		servingFunc: func(srv *mcpServer) error {
			logger.Infof("Starting MCP server with SSE transport: %s", config.SseServerAddr)
			s := server.NewSSEServer(srv.server, server.WithStaticBasePath(config.SseServerBasePath))

			// Wrap the SSE server with HEAD request support
			wrappedHandler := sseHandlerWithHeadSupport(s)
			wrappedHandler = hostGuard(wrappedHandler)
			wrappedHandler = originGuard(wrappedHandler)

			httpServer := &http.Server{
				Addr:    config.SseServerAddr,
				Handler: wrappedHandler,
			}

			return httpServer.ListenAndServe()
		},
	}, nil
}
