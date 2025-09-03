package server

import (
	"net/http"
	"slices"
	"strings"
)

// hostGuard is a middleware that allows only the allowed hosts to access the
// MCP server. nil config.SseServerAllowedHosts will use the default allowed hosts. Empty
// config.SseServerAllowedHosts will block all hosts.
func hostGuard(config McpServerConfig, next http.Handler) http.Handler {
	allowedHosts := config.SseServerAllowedHosts

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// contains is faster than a map lookup for small lists
		if !slices.Contains(allowedHosts, r.Host) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originGuard is a middleware that allows only the allowed origins to access
// the MCP server. If allowedOriginsPrefix is nil or empty, all origins will be blocked.
func originGuard(config McpServerConfig, next http.Handler) http.Handler {
	allowedOriginsPrefix := config.SseServerAllowedOriginsPrefix

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o := r.Header.Get("Origin")
		if o == "" {
			// Non-browser/same-origin fetches may omit Origin. Don't block
			// solely on this.
			next.ServeHTTP(w, r)
			return
		}

		if !isAllowedOrigin(o, allowedOriginsPrefix) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isAllowedOrigin checks if the origin is in the allowed origins prefix list.
func isAllowedOrigin(origin string, allowedOriginsPrefix []string) bool {
	for _, allowedOriginPrefix := range allowedOriginsPrefix {
		if strings.HasPrefix(origin, allowedOriginPrefix) {
			return true
		}
	}
	return false
}
