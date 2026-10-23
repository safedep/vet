package githubci

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/ci"
)

func TestAnnotate(t *testing.T) {
	var b bytes.Buffer
	require.NoError(t, Annotate(&b, []ci.Annotation{
		{Path: "pnpm-lock.yaml", Line: 92, Title: "vet: Published 1 day ago", Text: "Keep version 12.8.2."},
		{Path: "a,b:c.yml", Title: "t", Text: "100%\n::error file=x::injected"},
	}))
	assert.Equal(t, "::error file=pnpm-lock.yaml,line=92,title=vet%3A Published 1 day ago::Keep version 12.8.2.\n"+
		"::error file=a%2Cb%3Ac.yml,title=t::100%25%0A::error file=x::injected\n", b.String())
}
