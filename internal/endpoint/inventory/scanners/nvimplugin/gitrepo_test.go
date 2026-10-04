package nvimplugin

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile writes content to a file, creating parent dirs, failing the test on error.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const testSHA = "d569072b2e39e0078b55ea56b133fb9a30d78bad"

// gitConfig returns a minimal .git/config with the given origin URL.
func gitConfig(url string) string {
	return "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = " + url + "\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
}

func TestReadGitClone_LooseRef(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	writeFile(t, filepath.Join(gitDir, "config"), gitConfig("git@github.com:folke/snacks.nvim.git"))
	writeFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/main\n")
	writeFile(t, filepath.Join(gitDir, "refs", "heads", "main"), testSHA+"\n")

	got := readGitClone(dir)
	if got.OriginURL != "git@github.com:folke/snacks.nvim.git" {
		t.Errorf("OriginURL = %q", got.OriginURL)
	}
	if got.Head != testSHA {
		t.Errorf("Head = %q, want %q", got.Head, testSHA)
	}
}

func TestReadGitClone_PackedRefsFallback(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	writeFile(t, filepath.Join(gitDir, "config"), gitConfig("https://github.com/o/r.git"))
	writeFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/main\n")
	// No loose ref; only packed-refs, including a peeled tag line to skip.
	writeFile(t, filepath.Join(gitDir, "packed-refs"),
		"# pack-refs with: peeled fully-peeled sorted\n"+
			testSHA+" refs/heads/main\n"+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/tags/v1\n"+
			"^bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n")

	got := readGitClone(dir)
	if got.Head != testSHA {
		t.Errorf("Head = %q, want %q", got.Head, testSHA)
	}
}

func TestReadGitClone_DetachedHead(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	writeFile(t, filepath.Join(gitDir, "config"), gitConfig("https://github.com/o/r.git"))
	writeFile(t, filepath.Join(gitDir, "HEAD"), testSHA+"\n")

	got := readGitClone(dir)
	if got.Head != testSHA {
		t.Errorf("Head = %q, want %q", got.Head, testSHA)
	}
}

func TestReadGitClone_GitFilePointer(t *testing.T) {
	dir := t.TempDir()
	// Real git dir lives elsewhere; pluginDir/.git is a file pointing to it.
	realGit := filepath.Join(dir, "storage", "worktrees", "plugin")
	writeFile(t, filepath.Join(realGit, "config"), gitConfig("https://github.com/o/r.git"))
	writeFile(t, filepath.Join(realGit, "HEAD"), testSHA+"\n")

	pluginDir := filepath.Join(dir, "plugin")
	writeFile(t, filepath.Join(pluginDir, ".git"), "gitdir: "+realGit+"\n")

	got := readGitClone(pluginDir)
	if got.OriginURL != "https://github.com/o/r.git" {
		t.Errorf("OriginURL = %q", got.OriginURL)
	}
	if got.Head != testSHA {
		t.Errorf("Head = %q, want %q", got.Head, testSHA)
	}
}

func TestReadGitClone_NoGitDir(t *testing.T) {
	got := readGitClone(t.TempDir())
	if got != (gitClone{}) {
		t.Errorf("expected zero gitClone, got %+v", got)
	}
}

func TestReadGitClone_CorruptConfigDegrades(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	// A config with no origin remote: HEAD still resolves, origin is empty.
	writeFile(t, filepath.Join(gitDir, "config"), "[core]\n\trepositoryformatversion = 0\n")
	writeFile(t, filepath.Join(gitDir, "HEAD"), testSHA+"\n")

	got := readGitClone(dir)
	if got.OriginURL != "" {
		t.Errorf("OriginURL = %q, want empty", got.OriginURL)
	}
	if got.Head != testSHA {
		t.Errorf("Head = %q, want %q", got.Head, testSHA)
	}
}

func TestGitHeadCommit_Unresolvable(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	// Symbolic HEAD but no matching loose ref or packed-refs.
	writeFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/missing\n")
	if got := gitHeadCommit(gitDir); got != "" {
		t.Errorf("Head = %q, want empty", got)
	}
}
