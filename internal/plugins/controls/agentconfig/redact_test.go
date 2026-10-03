package agentconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedact(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"db": {"command": "node", "env": {"DB_URL": "postgres://u:pw@h/db", "MODE": "x"}}}`, `{"db": {"command": "node", "env": {"DB_URL": "***", "MODE": "***"}}}`},
		{`"headers": {"Authorization": "Bearer abc"}`, `"headers": {"Authorization": "***"}`},
		{`"GITHUB_TOKEN": "ghp_123",`, `"GITHUB_TOKEN": "***",`},
		{`"url": "https://user:secret@mcp.example.com/sse"`, `"url": "https://***@mcp.example.com/sse"`},
		{`"command": "npm run build",`, `"command": "npm run build",`},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, redact(tc.in))
	}
}
