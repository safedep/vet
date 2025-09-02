package server

import (
	"net/http"
	"slices"
	"strings"
)

var (
	defaultAllowedOriginsPrefix = []string{
		"http://localhost:",
		"http://127.0.0.1:",
		"https://localhost:",
	}
	defaultAllowedHosts = []string{"localhost:9988", "127.0.0.1:9988", "[::1]:9988"}
)

// hostGuard is a middleware that allows only the allowed hosts to access the
// MCP server. nil allowedHosts will use the default allowed hosts.  Empty
// allowedHosts will block all hosts.
func hostGuard(allowedHosts []string, next http.Handler) http.Handler {
	if allowedHosts == nil {
		allowedHosts = defaultAllowedHosts
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// contains is faster than a map lookup for small lists
		if !slices.Contains(allowedHosts, r.Host) {
			// 421 (misdirected request) is ideal; 403 (forbidden) is fine too.
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originGuard is a middleware that allows only the allowed origins to access
// the MCP server. nil allowedOriginsPrefix will use the default allowed origins
// prefix. Empty allowedOriginsPrefix will block all origins.
func originGuard(allowedOriginsPrefix []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o := r.Header.Get("Origin")
		if o == "" {
			// Non-browser/same-origin fetches may omit Origin. Don't block
			// solely on this.
			next.ServeHTTP(w, r)
			return
		}

		if allowedOriginsPrefix == nil {
			allowedOriginsPrefix = defaultAllowedOriginsPrefix
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
