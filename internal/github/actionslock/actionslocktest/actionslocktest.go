// Package actionslocktest writes GitHub Actions lockfiles for tests.
package actionslocktest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Lock is the content of a lockfile.
type Lock struct {
	// Workflows maps a workflow key to the keys, as owner/repo@ref, that it
	// uses.
	Workflows map[string][]string
	// Commits sets the commit SHA of a key. A key with a commit SHA as its
	// ref gets that SHA, and each other key a commit made from its name.
	Commits map[string]string
	// Hosts sets the hostname of a key.
	Hosts map[string]string
}

// String returns the lockfile in the format that gh actions-lock writes.
func (l Lock) String() string {
	var b strings.Builder
	b.WriteString("version: 'v0.0.3'\nworkflows:\n")
	deps := map[string]bool{}
	for _, w := range slices.Sorted(maps.Keys(l.Workflows)) {
		keys := l.Workflows[w]
		if len(keys) == 0 {
			fmt.Fprintf(&b, "    '%s': []\n", w)
			continue
		}
		fmt.Fprintf(&b, "    '%s':\n", w)
		for _, k := range keys {
			fmt.Fprintf(&b, "        - '%s'\n", k)
			deps[k] = true
		}
	}
	b.WriteString("dependencies:\n")
	for i, k := range slices.Sorted(maps.Keys(deps)) {
		_, ref, _ := strings.Cut(k, "@")
		fmt.Fprintf(&b, "    '%s':\n", k)
		if h := l.Hosts[k]; h != "" {
			fmt.Fprintf(&b, "        hostname: '%s'\n", h)
		}
		fmt.Fprintf(&b, "        ref: '%s'\n        commit: 'sha1-%s'\n        owner_id: 101\n        repo_id: %d\n", ref, l.commit(k), 201+i)
	}
	return b.String()
}

func (l Lock) commit(key string) string {
	if c, ok := l.Commits[key]; ok {
		return c
	}
	if _, ref, _ := strings.Cut(key, "@"); len(ref) == 40 {
		if _, err := hex.DecodeString(ref); err == nil {
			return strings.ToLower(ref)
		}
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:20])
}
