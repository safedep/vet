package agentconfig_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestManyCommandsOnOneLine keeps a minified file of many commands fast.
func TestManyCommandsOnOneLine(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"tasks":[`)
	for b.Len() < 1<<20-100 {
		b.WriteString(`{"command":"a000123 b"},`)
	}
	b.WriteString(`{"command":"x"}]}`)
	start := time.Now()
	got := testFile(t, ".vscode/tasks.json", b.String())
	assert.Len(t, got, 501)
	assert.Less(t, time.Since(start), 5*time.Second)
}

// TestLargeClaudeUserConfigIsFast keeps the read of a .claude.json at its
// 64 MiB limit linear, with many servers and a syntax error at the end. A
// read that costs a pass for each server takes minutes. The budget leaves
// room for a slow runner.
func TestLargeClaudeUserConfigIsFast(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"mcpServers": {`)
	for i := range 600 {
		if i > 0 {
			b.WriteString(",\n")
		}
		fmt.Fprintf(&b, `"s%d": {"command": "npx"}`, i)
	}
	b.WriteString("},\n\"projects\": {\"/a\": {\"history\": [")
	for b.Len() < 63<<20 {
		b.WriteString("\"abcdefghij klmnopqrst uvwxyz0123 456789\",\n")
	}
	full := b.String() + `"end"]}}}`
	cases := []struct {
		name, data string
		want       int
	}{
		{"valid", full, 501},
		{"broken at the end", full[:len(full)-1], 1},
		{"one line", strings.ReplaceAll(full, "\n", " "), 501},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			got := testFile(t, ".claude.json", tc.data)
			assert.Len(t, got, tc.want, "500 servers and one unreadable finding, or the unreadable finding alone")
			assert.Less(t, time.Since(start), 20*time.Second)
		})
	}
}
