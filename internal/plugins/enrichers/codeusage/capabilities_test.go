package codeusage

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/gitbase/gitbasetest"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// lineAnalyzer matches the signature <id> on each line "call <id>" of the
// files under dir. It skips installed code, as the real analyzer does, and
// records the files of each analysis.
type lineAnalyzer struct{ runs [][]string }

func (l *lineAnalyzer) analyze(_ context.Context, dir string) (Analysis, error) {
	var out Analysis
	var files []string
	defer func() { l.runs = append(l.runs, files) }()
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		files = append(files, relTo(dir, p))
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		sc := bufio.NewScanner(f)
		for line := 1; sc.Scan(); line++ {
			if id, ok := strings.CutPrefix(sc.Text(), "call "); ok {
				out.Matches = append(out.Matches, Match{
					Signature: Signature{ID: id, Vendor: "V", Product: "P", Tags: []string{"ai"}},
					FilePath:  p, Line: line, Column: 1, Language: "python", Callee: id,
				})
			}
		}
		return sc.Err()
	})
	return out, err
}

func ids(caps []report.Capability) map[string]model.Change {
	out := map[string]model.Change{}
	for _, c := range caps {
		out[c.ID] = c.Change
	}
	return out
}

func TestCapabilitiesOfAFullScan(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	for i := 0; i < maxOccurrences+5; i++ {
		lines = append(lines, "call openai.client")
	}
	gitbasetest.Write(t, dir, "b.py", strings.Join(lines, "\n"))
	gitbasetest.Write(t, dir, "a.py", "call openai.client\ncall anthropic.client\ncall anthropic.client\n")
	la := &lineAnalyzer{}
	caps, err := NewWith(dir, Options{}, la.analyze).Capabilities(context.Background())
	require.NoError(t, err)

	require.Len(t, caps, 2)
	assert.Equal(t, "anthropic.client", caps[0].ID, "capabilities are in id order")
	assert.Equal(t, []report.Occurrence{
		{File: "a.py", Line: 2, Column: 1, Language: "python", Callee: "anthropic.client"},
		{File: "a.py", Line: 3, Column: 1, Language: "python", Callee: "anthropic.client"},
	}, caps[0].Occurrences)
	assert.Len(t, caps[1].Occurrences, maxOccurrences)
	assert.Equal(t, report.Occurrence{File: "a.py", Line: 1, Column: 1, Language: "python", Callee: "openai.client"}, caps[1].Occurrences[0])
	assert.Empty(t, caps[1].Change, "a full scan has no change")
	assert.Equal(t, []string{"ai"}, caps[1].Tags)
}

func TestCapabilitiesOfAPullRequest(t *testing.T) {
	dir := gitbasetest.Repo(t, map[string]string{
		"kept.py":                  "call openai.client\n",
		"crlf.py":                  "x = 1\ny = 2\n",
		"edited.py":                "call langchain.chain\n",
		"gone.py":                  "call cohere.client\n",
		"node_modules/lib/x.py":    "call mistral.client\n",
		"moved/unchanged/other.py": "x = 1\n",
	})
	gitbasetest.Write(t, dir, "edited.py", "call anthropic.client\n")
	gitbasetest.Write(t, dir, "crlf.py", "x = 1\r\ny = 2\r\n")
	gitbasetest.Write(t, dir, "new.py", "call openai.client\ncall groq.client\n")
	require.NoError(t, os.Remove(filepath.Join(dir, "gone.py")))

	la := &lineAnalyzer{}
	caps, err := NewWith(dir, Options{BaseRef: "HEAD"}, la.analyze).Capabilities(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]model.Change{
		"openai.client":    model.ChangeUnchanged,
		"anthropic.client": model.ChangeAdded,
		"groq.client":      model.ChangeAdded,
		"langchain.chain":  model.ChangeRemoved,
		"cohere.client":    model.ChangeRemoved,
	}, ids(caps))

	require.Len(t, la.runs, 2, "the head, then the changed base files")
	assert.ElementsMatch(t, []string{"edited.py", "gone.py"}, la.runs[1], "an unchanged or installed file needs no base analysis")
	for _, c := range caps {
		if c.ID == "langchain.chain" {
			assert.Equal(t, "edited.py", c.Occurrences[0].File, "a removed capability lists the base calls")
		}
	}
}

func TestOneCallMatchesTwoSignatures(t *testing.T) {
	call := Match{FilePath: "a.py", Line: 3, Callee: "openai//OpenAI"}
	client, sync := call, call
	client.Signature.ID, sync.Signature.ID = "openai.client", "openai.sync"
	caps := group([]Match{client, sync, client})
	require.Len(t, caps, 2)
	assert.Len(t, caps["openai.client"].Occurrences, 1)
	assert.Len(t, caps["openai.sync"].Occurrences, 1, "each signature lists the call")
}

func TestCapabilitiesNeedGitInPullRequestMode(t *testing.T) {
	la := &lineAnalyzer{}
	_, err := NewWith(t.TempDir(), Options{BaseRef: "main"}, la.analyze).Capabilities(context.Background())
	assert.Error(t, err)
}

func TestCapabilitiesAnalyzeOnce(t *testing.T) {
	dir := t.TempDir()
	gitbasetest.Write(t, dir, "a.py", "call openai.client\n")
	la := &lineAnalyzer{}
	e := NewWith(dir, Options{}, la.analyze)
	require.NoError(t, e.Enrich(context.Background(), nil))
	_, err := e.Capabilities(context.Background())
	require.NoError(t, err)
	assert.Len(t, la.runs, 1, "usage and capabilities share one analysis")
}
