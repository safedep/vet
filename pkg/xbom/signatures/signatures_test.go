package signatures_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	signatures "github.com/safedep/vet/pkg/xbom/signatures"
	_ "github.com/safedep/vet/signatures" // triggers embed registration
)

func TestLoadAllSignatures(t *testing.T) {
	sigs, err := signatures.LoadAllSignatures()
	require.NoError(t, err)
	assert.NotEmpty(t, sigs, "Expected signatures to be loaded")

	// Verify no duplicate IDs
	seen := map[string]bool{}
	for _, sig := range sigs {
		assert.NotEmpty(t, sig.Id, "Signature ID should not be empty")
		assert.False(t, seen[sig.Id], "Duplicate signature ID: %s", sig.Id)
		seen[sig.Id] = true
	}
}

func TestLoadSignaturesByVendor(t *testing.T) {
	cases := []struct {
		name     string
		vendor   string
		product  string
		service  string
		minCount int
	}{
		{"all Go signatures", "lang/golang", "", "", 1},
		{"all Python signatures", "lang/python", "", "", 1},
		{"all JavaScript signatures", "lang/javascript", "", "", 1},
		{"OpenAI signatures", "openai", "", "", 1},
		{"Anthropic signatures", "anthropic", "", "", 1},
		{"Google GCP signatures", "google", "", "", 1},
		{"Microsoft signatures", "microsoft", "", "", 1},
		{"Cryptography signatures", "cryptography", "", "", 1},
		{"LangChain signatures", "langchain", "", "", 1},
		{"CrewAI signatures", "crewai", "", "", 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sigs, err := signatures.LoadSignatures(tc.vendor, tc.product, tc.service)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(sigs), tc.minCount,
				"Expected at least %d signatures for %s", tc.minCount, tc.vendor)
		})
	}
}

func TestLoadSignaturesValidation(t *testing.T) {
	// All loaded signatures must pass protobuf validation
	sigs, err := signatures.LoadAllSignatures()
	require.NoError(t, err)

	for _, sig := range sigs {
		assert.NotEmpty(t, sig.Id, "Signature must have an ID")
		assert.NotNil(t, sig.Languages, "Signature %s must have language matchers", sig.Id)
		assert.NotEmpty(t, sig.Languages, "Signature %s must have at least one language", sig.Id)
	}
}

func TestLoadSignaturesSingleFile(t *testing.T) {
	// Load a specific service file: vendor="lang", product="golang", service="filesystem"
	// This constructs the path: lang/golang/filesystem.yaml
	sigs, err := signatures.LoadSignatures("lang", "golang", "filesystem")
	require.NoError(t, err)
	assert.NotEmpty(t, sigs, "Expected filesystem signatures for Go")

	// Verify we got filesystem-related signatures
	for _, sig := range sigs {
		assert.Contains(t, sig.Id, "golang.filesystem",
			"Expected Go filesystem signatures, got %s", sig.Id)
	}
}
