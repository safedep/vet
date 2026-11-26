package render

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDocsRef(t *testing.T) {
	cases := map[string]string{
		"2.0.0":                              "v2.0.0",
		"v2.1.3":                             "v2.1.3",
		"2.0.0-alpha.20261005063951":         "v2.0.0-alpha.20261005063951",
		"devel":                              devRef,
		"v2.0.0-20261005063951-abcdefabcdef": devRef,
		"2.0.0+dirty":                        devRef,
	}
	for version, want := range cases {
		assert.Equal(t, want, DocsRef(version), version)
	}
	assert.Equal(t, "https://github.com/safedep/vet/blob/v2.1.3/docs/controls.md#unicode-payload", ControlURL("2.1.3", "unicode-payload"))
}
