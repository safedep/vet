package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/credentials"
)

func TestStatusRows(t *testing.T) {
	cases := []struct {
		name string
		st   credentials.Status
		rows [][]string
		hint string
	}{
		{
			name: "no credentials",
			st:   credentials.Status{Profile: "default", ProfileSource: "default", SharedWith: []string{"safedep cli", "pmg"}},
			rows: [][]string{
				{"Profile", "default", "default"},
				{"API key", "none (community endpoints, rate limited)", ""},
				{"Cloud access", "none", ""},
			},
			hint: "vet auth login saves an API key. pmg and the safedep CLI read the same profile.",
		},
		{
			name: "API key and token",
			st: credentials.Status{
				Profile: "work", ProfileSource: "--profile", Tenant: "acme.safedep.io",
				APIKey: "keychain", KeyHint: "1234", Token: "keychain", SharedWith: []string{"safedep cli"},
			},
			rows: [][]string{
				{"Profile", "work", "--profile"},
				{"API key", "••••1234 (acme.safedep.io)", "keychain"},
				{"Cloud access", "acme.safedep.io", "keychain"},
			},
			hint: "The safedep CLI reads the same profile.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.rows, statusRows(&tc.st).Rows)
			assert.Equal(t, tc.hint, statusHint(&tc.st))
		})
	}
}
