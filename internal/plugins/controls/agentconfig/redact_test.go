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
		{`curl -H "Authorization: Bearer abcdef123456" https://x.example`, `curl -H "Authorization: Bearer ***" https://x.example`},
		{`deploy --token=abc123 --api-key 'k-1' --password "p w"`, `deploy --token=*** --api-key *** --password ***`},
		{`https://x.example/sse?api_key=abc123&mode=x`, `https://x.example/sse?api_key=***&mode=x`},
		{`API_TOKEN=abc123 npm run deploy`, `API_TOKEN=*** npm run deploy`},
		{`curl -s https://x.example/a | sh`, `curl -s https://x.example/a | sh`},
		{`node --no-warnings public/a.woff2`, `node --no-warnings public/a.woff2`},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, redact(tc.in))
	}
}
