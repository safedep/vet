package tui

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/ent"
)

func newTestRenderer(width int) *QueryResultRenderer {
	return &QueryResultRenderer{
		styles: NewStyles(DefaultProfile),
		width:  width,
	}
}

func newMatch(sigID, lang, filePath string, line uint, matchedCall string, tags []string) *ent.CodeSignatureMatch {
	return &ent.CodeSignatureMatch{
		SignatureID: sigID,
		Language:    lang,
		FilePath:    filePath,
		Line:        line,
		MatchedCall: matchedCall,
		Tags:        tags,
	}
}

func TestRenderMatchesEmpty(t *testing.T) {
	r := newTestRenderer(120)
	output := r.RenderMatches(nil, 50)

	assert.Contains(t, output, "0 matches found")
	assert.Contains(t, output, "50 total")
	assert.NotContains(t, output, "Signature ID")
}

func TestRenderMatchesEmptyZeroTotal(t *testing.T) {
	r := newTestRenderer(120)
	output := r.RenderMatches(nil, 0)

	assert.Contains(t, output, "0 matches found")
}

func TestRenderMatchesShowsHeader(t *testing.T) {
	r := newTestRenderer(120)
	matches := []*ent.CodeSignatureMatch{
		newMatch("golang.crypto.sha256", "go", "pkg/auth/hash.go", 42, "crypto/sha256/New", []string{"crypto"}),
	}

	output := r.RenderMatches(matches, 1)

	assert.Contains(t, output, "Signature ID")
	assert.Contains(t, output, "Language")
	assert.Contains(t, output, "File Path")
	assert.Contains(t, output, "Line")
	assert.Contains(t, output, "Matched Call")
}

func TestRenderMatchesShowsData(t *testing.T) {
	r := newTestRenderer(140)
	matches := []*ent.CodeSignatureMatch{
		newMatch("golang.crypto.sha256", "go", "pkg/auth/hash.go", 42, "crypto/sha256/New", []string{"crypto"}),
		newMatch("python.openai.client", "python", "src/api/inference.py", 7, "openai/Client", []string{"ai", "llm"}),
	}

	output := r.RenderMatches(matches, 2)

	assert.Contains(t, output, "golang.crypto.sha256")
	assert.Contains(t, output, "python.openai.client")
	assert.Contains(t, output, "pkg/auth/hash.go")
	assert.Contains(t, output, "src/api/inference.py")
	assert.Contains(t, output, "42")
	assert.Contains(t, output, "7")
	assert.Contains(t, output, "crypto/sha256/New")
	assert.Contains(t, output, "openai/Client")
}

func TestRenderMatchesFooterNoTruncation(t *testing.T) {
	r := newTestRenderer(120)
	matches := []*ent.CodeSignatureMatch{
		newMatch("sig1", "go", "a.go", 1, "call1", nil),
		newMatch("sig2", "go", "b.go", 2, "call2", nil),
	}

	// totalCount == len(matches), no truncation
	output := r.RenderMatches(matches, 2)

	assert.Contains(t, output, "2")
	assert.Contains(t, output, "matches found")
	assert.NotContains(t, output, "--limit")
}

func TestRenderMatchesFooterWithTruncation(t *testing.T) {
	r := newTestRenderer(120)
	matches := []*ent.CodeSignatureMatch{
		newMatch("sig.a", "go", "a.go", 1, "callA", nil),
		newMatch("sig.b", "go", "b.go", 2, "callB", nil),
	}

	// totalCount > len(matches), means DB limit was applied
	output := r.RenderMatches(matches, 100)

	assert.Contains(t, output, "2")
	assert.Contains(t, output, "of 100 matches shown")
	assert.Contains(t, output, "--limit")
}

func TestRenderMatchesShowsTagsWideTerminal(t *testing.T) {
	r := newTestRenderer(120)
	matches := []*ent.CodeSignatureMatch{
		newMatch("sig1", "go", "a.go", 1, "call1", []string{"ai", "llm"}),
	}

	output := r.RenderMatches(matches, 1)

	assert.Contains(t, output, "Tags")
	assert.Contains(t, output, "ai")
	assert.Contains(t, output, "llm")
}

func TestRenderMatchesHidesTagsNarrowTerminal(t *testing.T) {
	r := newTestRenderer(90)
	matches := []*ent.CodeSignatureMatch{
		newMatch("sig1", "go", "a.go", 1, "call1", []string{"ai"}),
	}

	output := r.RenderMatches(matches, 1)

	assert.NotContains(t, output, "Tags")
}

func TestRenderMatchesSeparator(t *testing.T) {
	r := newTestRenderer(120)
	matches := []*ent.CodeSignatureMatch{
		newMatch("sig1", "go", "a.go", 1, "call1", nil),
	}

	output := r.RenderMatches(matches, 1)

	assert.Contains(t, output, "───")
}

func TestTruncateLeft(t *testing.T) {
	assert.Equal(t, "short", truncateLeft("short", 20))
	assert.Equal(t, "...long_path.go", truncateLeft("very/deeply/nested/long_path.go", 15))
	assert.Equal(t, "...h", truncateLeft("abcdefgh", 4))
}

func TestTruncateRight(t *testing.T) {
	assert.Equal(t, "short", truncateRight("short", 20))
	assert.Equal(t, "crypto/sha2...", truncateRight("crypto/sha256/New", 14))
	assert.Equal(t, "a...", truncateRight("abcdefgh", 4))
}

func TestTruncateLeftMinWidth(t *testing.T) {
	result := truncateLeft("abcdefgh", 2)
	assert.Equal(t, "...h", result)
}

func TestTruncateRightMinWidth(t *testing.T) {
	result := truncateRight("abcdefgh", 2)
	assert.Equal(t, "a...", result)
}

func TestRenderMatchesFilePathTruncation(t *testing.T) {
	r := newTestRenderer(80)
	longPath := "very/deeply/nested/directory/structure/with/many/levels/source_file.go"
	matches := []*ent.CodeSignatureMatch{
		newMatch("sig1", "go", longPath, 1, "call1", nil),
	}

	output := r.RenderMatches(matches, 1)

	assert.Contains(t, output, "...")
	assert.Contains(t, output, "source_file.go")
}

func TestRenderMatchesMultipleMatches(t *testing.T) {
	r := newTestRenderer(140)
	matches := []*ent.CodeSignatureMatch{
		newMatch("sig.a", "go", "a.go", 10, "pkg/FuncA", []string{"crypto"}),
		newMatch("sig.b", "python", "b.py", 20, "mod.func_b", []string{"ai"}),
		newMatch("sig.c", "go", "c.go", 30, "pkg/FuncC", nil),
	}

	output := r.RenderMatches(matches, 3)

	assert.Contains(t, output, "sig.a")
	assert.Contains(t, output, "sig.b")
	assert.Contains(t, output, "sig.c")

	// Verify ordering (sig.a before sig.b before sig.c)
	idxA := strings.Index(output, "sig.a")
	idxB := strings.Index(output, "sig.b")
	idxC := strings.Index(output, "sig.c")
	assert.Greater(t, idxB, idxA)
	assert.Greater(t, idxC, idxB)

	assert.Contains(t, output, "3")
	assert.Contains(t, output, "matches found")
}
