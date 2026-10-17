package archtest

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// credentialURL is a URL with a user and a password, as the URI detector of
// TruffleHog reads it. The secret scan of a pull request fails on each one
// that it cannot verify, and a fake credential cannot be verified.
var credentialURL = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@'"` + "`" + `]{0,50}:([^\s@'"` + "`" + `]{3,50})@[a-zA-Z0-9.-]+`)

// TestRepoHoldsNoCredentialURL keeps the fake credentials of the tests and
// the examples of the comments out of the secret scan. TruffleHog skips a
// URL whose password is all "*" or starts with "$", and a line with the tag
// trufflehog:ignore. Each file uses one of them. A path exclusion would
// hide a real secret.
func TestRepoHoldsNoCredentialURL(t *testing.T) {
	root := repoRoot(t)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(p, root+string(filepath.Separator)))
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer func() { assert.NoError(t, f.Close()) }()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
		for n := 1; sc.Scan(); n++ {
			line := sc.Text()
			if strings.ContainsRune(line, 0) {
				return nil
			}
			if strings.Contains(line, "trufflehog:ignore") {
				continue
			}
			for _, m := range credentialURL.FindAllStringSubmatch(line, -1) {
				if pw := m[1]; strings.Trim(pw, "*") != "" && !strings.HasPrefix(pw, "$") {
					assert.Fail(t, "a file holds a credential URL that the secret scan reports",
						"%s:%d: %s. Use the password ***, a $VAR, or the tag trufflehog:ignore on the line.", rel, n, m[0])
				}
			}
		}
		return sc.Err()
	})
	require.NoError(t, err)
}
