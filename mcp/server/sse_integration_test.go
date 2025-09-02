package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSEServerIntegration(t *testing.T) {
	// Create a test MCP server
	mcpServer := server.NewMCPServer("test-vet-mcp", "0.0.1",
		server.WithInstructions("Test MCP server for integration testing"))

	// Create SSE server with our custom handler and wrap with guards
	sseServer := server.NewSSEServer(mcpServer, server.WithStaticBasePath(""))
	baseHandler := sseHandlerWithHeadSupport(sseServer)

	// Use an unstarted server with a custom listener so we know the allowed host
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	allowedHost := listener.Addr().String()

	// Apply guards in the same order as production code: origin, then host
	wrappedHandler := originGuard(nil, baseHandler)
	wrappedHandler = hostGuard([]string{allowedHost}, wrappedHandler)

	// Create and start test server
	testServer := httptest.NewUnstartedServer(wrappedHandler)
	testServer.Listener = listener
	testServer.Start()
	t.Cleanup(func() {
		testServer.Close()
	})

	t.Run("HEAD request to SSE endpoint", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodHead, testServer.URL+"/sse", nil)
		require.NoError(t, err)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, resp.Body.Close())
		})

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Check SSE headers are present
		assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
		assert.Equal(t, "no-cache", resp.Header.Get("Cache-Control"))
		assert.Equal(t, "keep-alive", resp.Header.Get("Connection"))
		assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))

		// Verify no body was returned for HEAD request (ContentLength -1 is expected for HEAD)
		assert.True(t, resp.ContentLength <= 0, "HEAD request should not have content length > 0")
	})

	t.Run("GET request with invalid host should be blocked", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, testServer.URL+"/sse", nil)
		require.NoError(t, err)
		// Override host header to simulate a different host
		req.Host = "example.com:9988"

		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, resp.Body.Close())
		})

		assert.Equal(t, http.StatusMisdirectedRequest, resp.StatusCode)
	})

	t.Run("GET request with invalid origin should be blocked", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, testServer.URL+"/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "http://example.com")

		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, resp.Body.Close())
		})

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("GET request to SSE endpoint", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, testServer.URL+"/sse", nil)
		require.NoError(t, err)

		// Use a context with timeout to avoid hanging
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req = req.WithContext(ctx)

		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, resp.Body.Close())
		})

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Check SSE headers are present
		assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
		assert.Equal(t, "no-cache", resp.Header.Get("Cache-Control"))
		assert.Equal(t, "keep-alive", resp.Header.Get("Connection"))
		assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	})

	t.Run("POST request to SSE endpoint should be handled by original handler", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, testServer.URL+"/sse", nil)
		require.NoError(t, err)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, resp.Body.Close())
		})

		// POST to SSE endpoint should return 405 Method Not Allowed since SSE only accepts GET/HEAD
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	})

	t.Run("HEAD request to message endpoint should not be handled specially", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodHead, testServer.URL+"/message", nil)
		require.NoError(t, err)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, resp.Body.Close())
		})

		// HEAD requests to message endpoint should be handled by original SSE server handler
		// which returns 400 Bad Request because message handler expects POST with sessionId parameter
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}
