package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSSEHandlerWithHeadSupport(t *testing.T) {
	// Create a mock SSE handler that would normally handle GET requests
	mockSSEHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("event: endpoint\ndata: /message?sessionId=test\n\n"))
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Wrap the mock handler with HEAD support
	wrappedHandler := sseHandlerWithHeadSupport(mockSSEHandler)

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		expectedHeaders map[string]string
		expectBody     bool
	}{
		{
			name:           "HEAD request to SSE endpoint should return SSE headers without body",
			method:         http.MethodHead,
			path:           "/sse",
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"Content-Type":                "text/event-stream",
				"Cache-Control":               "no-cache",
				"Connection":                  "keep-alive",
				"Access-Control-Allow-Origin": "*",
			},
			expectBody: false,
		},
		{
			name:           "GET request to SSE endpoint should work normally",
			method:         http.MethodGet,
			path:           "/sse",
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"Content-Type":                "text/event-stream",
				"Cache-Control":               "no-cache",
				"Connection":                  "keep-alive",
				"Access-Control-Allow-Origin": "*",
			},
			expectBody: true,
		},
		{
			name:           "POST request to SSE endpoint should be rejected",
			method:         http.MethodPost,
			path:           "/sse",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedHeaders: map[string]string{},
			expectBody:     true, // Error message body
		},
		{
			name:           "HEAD request to non-SSE endpoint should be passed through",
			method:         http.MethodHead,
			path:           "/message",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedHeaders: map[string]string{},
			expectBody:     true, // Error message body
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			// Check expected headers
			for key, expectedValue := range tt.expectedHeaders {
				assert.Equal(t, expectedValue, w.Header().Get(key), "Header %s mismatch", key)
			}

			// Check body presence
			body := w.Body.String()
			if tt.expectBody {
				assert.NotEmpty(t, body, "Expected body to be present")
			} else {
				assert.Empty(t, body, "Expected body to be empty for HEAD request")
			}
		})
	}
}

func TestMcpServerWithSseTransport(t *testing.T) {
	config := DefaultMcpServerConfig()
	config.SseServerAddr = "localhost:0" // Use random available port for testing

	srv, err := NewMcpServerWithSseTransport(config)
	assert.NoError(t, err)
	assert.NotNil(t, srv)

	// Verify that the server instance is properly configured
	assert.Equal(t, config, srv.config)
	assert.NotNil(t, srv.server)
	assert.NotNil(t, srv.servingFunc)
}