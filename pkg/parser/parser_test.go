package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestListParser(t *testing.T) {
	parsers := List()
	assert.Equal(t, 9, len(parsers))
}

func TestInvalidEcosystemMapping(t *testing.T) {
	pw := &parserWrapper{parseAs: "nothing"}
	assert.Empty(t, pw.Ecosystem())
}

func TestEcosystemMapping(t *testing.T) {
	for _, lf := range List() {
		t.Run(lf, func(t *testing.T) {
			pw := &parserWrapper{parseAs: lf}
			assert.NotEmpty(t, pw.Ecosystem())
		})
	}
}
