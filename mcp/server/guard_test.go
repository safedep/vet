package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHostGuard(t *testing.T) {
	// Create a mock handler that just returns OK
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with host guard
	hostGuardedHandler := hostGuard(mockHandler)

	tests := []struct {
		name           string
		host           string
		expectedStatus int
		shouldAllow    bool
	}{
		{
			name:           "localhost:9988 should be allowed",
			host:           "localhost:9988",
			expectedStatus: http.StatusOK,
			shouldAllow:    true,
		},
		{
			name:           "127.0.0.1:9988 should be allowed",
			host:           "127.0.0.1:9988",
			expectedStatus: http.StatusOK,
			shouldAllow:    true,
		},
		{
			name:           "[::1]:9988 should be allowed",
			host:           "[::1]:9988",
			expectedStatus: http.StatusOK,
			shouldAllow:    true,
		},
		{
			name:           "different host should be blocked",
			host:           "example.com:9988",
			expectedStatus: http.StatusMisdirectedRequest,
			shouldAllow:    false,
		},
		{
			name:           "localhost with different port should be blocked",
			host:           "localhost:9999",
			expectedStatus: http.StatusMisdirectedRequest,
			shouldAllow:    false,
		},
		{
			name:           "127.0.0.1 with different port should be blocked",
			host:           "127.0.0.1:9999",
			expectedStatus: http.StatusMisdirectedRequest,
			shouldAllow:    false,
		},
		{
			name:           "IPv6 localhost with different port should be blocked",
			host:           "[::1]:9999",
			expectedStatus: http.StatusMisdirectedRequest,
			shouldAllow:    false,
		},
		{
			name:           "malicious host should be blocked",
			host:           "evil.com:9988",
			expectedStatus: http.StatusMisdirectedRequest,
			shouldAllow:    false,
		},
		{
			name:           "host without port should be blocked",
			host:           "localhost",
			expectedStatus: http.StatusMisdirectedRequest,
			shouldAllow:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = tt.host
			w := httptest.NewRecorder()

			hostGuardedHandler.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.shouldAllow {
				assert.Equal(
					t,
					http.StatusOK,
					w.Code,
					"Request should be allowed for host: %s",
					tt.host,
				)
			} else {
				assert.Equal(t, http.StatusMisdirectedRequest, w.Code, "Request should be blocked for host: %s", tt.host)
			}
		})
	}
}

func TestOriginGuard(t *testing.T) {
	// Create a mock handler that just returns OK
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with origin guard
	originGuardedHandler := originGuard(mockHandler)

	tests := []struct {
		name           string
		origin         string
		expectedStatus int
		shouldAllow    bool
	}{
		{
			name:           "http://localhost:3000 should be allowed",
			origin:         "http://localhost:3000",
			expectedStatus: http.StatusOK,
			shouldAllow:    true,
		},
		{
			name:           "http://127.0.0.1:3000 should be allowed",
			origin:         "http://127.0.0.1:3000",
			expectedStatus: http.StatusOK,
			shouldAllow:    true,
		},
		{
			name:           "https://localhost:3000 should be allowed",
			origin:         "https://localhost:3000",
			expectedStatus: http.StatusOK,
			shouldAllow:    true,
		},
		{
			name:           "http://localhost:8080 should be allowed",
			origin:         "http://localhost:8080",
			expectedStatus: http.StatusOK,
			shouldAllow:    true,
		},
		{
			name:           "no origin header should be allowed (non-browser requests)",
			origin:         "",
			expectedStatus: http.StatusOK,
			shouldAllow:    true,
		},
		{
			name:           "http://example.com should be blocked",
			origin:         "http://example.com",
			expectedStatus: http.StatusForbidden,
			shouldAllow:    false,
		},
		{
			name:           "https://example.com should be blocked",
			origin:         "https://example.com",
			expectedStatus: http.StatusForbidden,
			shouldAllow:    false,
		},
		{
			name:           "http://evil.com:3000 should be blocked",
			origin:         "http://evil.com:3000",
			expectedStatus: http.StatusForbidden,
			shouldAllow:    false,
		},
		{
			name:           "ftp://localhost:3000 should be blocked",
			origin:         "ftp://localhost:3000",
			expectedStatus: http.StatusForbidden,
			shouldAllow:    false,
		},
		{
			name:           "null origin should be blocked",
			origin:         "null",
			expectedStatus: http.StatusForbidden,
			shouldAllow:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			w := httptest.NewRecorder()

			originGuardedHandler.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.shouldAllow {
				assert.Equal(
					t,
					http.StatusOK,
					w.Code,
					"Request should be allowed for origin: %s",
					tt.origin,
				)
			} else {
				assert.Equal(t, http.StatusForbidden, w.Code, "Request should be blocked for origin: %s", tt.origin)
			}
		})
	}
}

func TestGuardsIntegration(t *testing.T) {
	// Create a mock handler that just returns OK
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with both guards (in the same order as used in sse.go)
	wrappedHandler := hostGuard(mockHandler)
	wrappedHandler = originGuard(wrappedHandler)

	tests := []struct {
		name           string
		host           string
		origin         string
		expectedStatus int
		shouldAllow    bool
	}{
		{
			name:           "valid host and origin should be allowed",
			host:           "localhost:9988",
			origin:         "http://localhost:3000",
			expectedStatus: http.StatusOK,
			shouldAllow:    true,
		},
		{
			name:           "invalid host should be blocked regardless of origin",
			host:           "example.com:9988",
			origin:         "http://localhost:3000",
			expectedStatus: http.StatusMisdirectedRequest,
			shouldAllow:    false,
		},
		{
			name:           "valid host but invalid origin should be blocked",
			host:           "localhost:9988",
			origin:         "http://example.com",
			expectedStatus: http.StatusForbidden,
			shouldAllow:    false,
		},
		{
			name:           "no origin header with valid host should be allowed",
			host:           "127.0.0.1:9988",
			origin:         "",
			expectedStatus: http.StatusOK,
			shouldAllow:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = tt.host
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			w := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.shouldAllow {
				assert.Equal(
					t,
					http.StatusOK,
					w.Code,
					"Request should be allowed for host=%s, origin=%s",
					tt.host,
					tt.origin,
				)
			}
		})
	}
}
