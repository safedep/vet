package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/internal/policy"
)

func TestStarterIsValid(t *testing.T) {
	p, err := policy.Parse("starter", []byte(policy.Starter))
	require.NoError(t, err)
	require.Len(t, p.Rules, 3)
	for _, r := range p.Rules {
		assert.Equal(t, policy.ScopeFinding, r.Scope(), "the starter has no cooldown rule and no package rule: %s", r.ID)
	}
}

func TestStarterNamesKnownControls(t *testing.T) {
	list, err := controls.Catalog()
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, c := range list {
		ids[c.ID] = true
	}
	for _, id := range []string{"malware", "suspicious-package", "vulnerability", "dangerous-trigger", "template-injection", "unpinned-action", "dependency-cooldown", "untrusted-registry"} {
		assert.True(t, ids[id], "control %s is listed", id)
	}
}
