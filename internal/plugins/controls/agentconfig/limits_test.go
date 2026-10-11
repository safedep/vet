package agentconfig_test

import (
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
