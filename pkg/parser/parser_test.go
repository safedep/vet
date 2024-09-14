package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestListParser(t *testing.T) {
	parsers := List(false)
	assert.Equal(t, 15, len(parsers))
}

func TestInvalidEcosystemMapping(t *testing.T) {
	pw := &parserWrapper{parseAs: "nothing"}
	assert.Empty(t, pw.Ecosystem())
}

func TestEcosystemMapping(t *testing.T) {
	for _, lf := range List(false) {
		t.Run(lf, func(t *testing.T) {
			// For graph parsers, we add a tag to the end of the name
			lf = strings.Split(lf, " ")[0]

			pw := &parserWrapper{parseAs: lf}
			assert.NotEmpty(t, pw.Ecosystem())
		})
	}
}
