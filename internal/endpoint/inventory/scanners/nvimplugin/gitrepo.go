package nvimplugin

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	gitconfig "github.com/go-git/go-git/v5/plumbing/format/config"
)

// gitClone holds the origin URL and HEAD commit read from a plugin's git
// clone. Every field is best-effort: a missing or malformed clone yields
// empty strings, never an error.
type gitClone struct {
	OriginURL string
	Head      string
}

// readGitClone reads the origin URL and HEAD commit for a plugin install,
// returning the zero gitClone when it is not a git clone.
func readGitClone(pluginDir string) gitClone {
	gitDir := resolveGitDir(pluginDir)
	if gitDir == "" {
		return gitClone{}
	}
	return gitClone{
		OriginURL: gitOriginURL(gitDir),
		Head:      gitHeadCommit(gitDir),
	}
}

// resolveGitDir returns the clone's git directory. For a .git file
// (worktree/submodule layout) it follows the single "gitdir: <path>"
// pointer. Returns "" when no resolvable git directory is present.
func resolveGitDir(pluginDir string) string {
	dotGit := filepath.Join(pluginDir, ".git")
	info, err := os.Stat(dotGit)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		return dotGit
	}

	data, err := os.ReadFile(dotGit)
	if err != nil {
		return ""
	}
	target, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir:")
	if !ok {
		return ""
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(pluginDir, target)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		return ""
	}
	return target
}

// gitOriginURL reads remote.origin.url from <gitDir>/config via go-git's
// hardened config parser. Returns "" on any failure.
func gitOriginURL(gitDir string) string {
	f, err := os.Open(filepath.Join(gitDir, "config"))
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	cfg := gitconfig.New()
	if err := gitconfig.NewDecoder(f).Decode(cfg); err != nil {
		return ""
	}
	return cfg.Section("remote").Subsection("origin").Option("url")
}

// gitHeadCommit resolves <gitDir>/HEAD to a commit SHA via loose ref,
// packed-refs, or a detached 40-hex HEAD. Returns "" when unresolvable.
func gitHeadCommit(gitDir string) string {
	data, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return ""
	}
	head := strings.TrimSpace(string(data))

	ref, ok := strings.CutPrefix(head, "ref:")
	if !ok {
		if isHexSHA(head) {
			return head
		}
		return ""
	}
	ref = strings.TrimSpace(ref)

	if looseData, err := os.ReadFile(filepath.Join(gitDir, filepath.FromSlash(ref))); err == nil {
		if sha := strings.TrimSpace(string(looseData)); isHexSHA(sha) {
			return sha
		}
	}

	return packedRefCommit(gitDir, ref)
}

// packedRefCommit scans <gitDir>/packed-refs for the SHA bound to ref,
// skipping comments and peeled-tag ('^') lines.
func packedRefCommit(gitDir, ref string) string {
	f, err := os.Open(filepath.Join(gitDir, "packed-refs"))
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' || line[0] == '^' {
			continue
		}
		sha, name, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if strings.TrimSpace(name) == ref && isHexSHA(sha) {
			return sha
		}
	}
	return ""
}

// isHexSHA reports whether s is a 40-character hex SHA-1.
func isHexSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
