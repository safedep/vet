package server

import (
	"net/http"
	"strings"
)

// hostGuard is a middleware that allows only the allowed hosts to access
// the MCP server.
func hostGuard(next http.Handler) http.Handler {
	allowedHosts := map[string]struct{}{
		"localhost:9988": {},
		"127.0.0.1:9988": {},
		"[::1]:9988":     {},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := allowedHosts[r.Host]; !ok {
			// 421 (misdirected request) is ideal; 403 (forbidden) is fine too.
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originGuard is a middleware that allows only the allowed origins to access
// the MCP server.
func originGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o := r.Header.Get("Origin")
		if o == "" {
			// Non-browser/same-origin fetches may omit Origin. Don't block
			// solely on this.
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(o, "http://localhost:") &&
			!strings.HasPrefix(o, "http://127.0.0.1:") &&
			!strings.HasPrefix(o, "https://localhost:") {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
