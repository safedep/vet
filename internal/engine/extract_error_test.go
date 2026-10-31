package engine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

func TestExtractErrorNamesAnUnknownEcosystem(t *testing.T) {
	_, perr := model.ParsePURL("pkg:git/github.com/argoproj/argo-ui@28927a5")
	require.ErrorIs(t, perr, model.ErrUnknownEcosystem)
	r := &run{diags: newDiagnostics()}
	r.extractError(fmt.Errorf("ui/pnpm-lock.yaml: %w", perr), model.ChangeUnchanged)
	r.extractError(fmt.Errorf("lock.yaml: %w", perr), model.ChangeUnchanged)

	require.Len(t, r.diags.order, 1)
	d := r.diags.byKey[r.diags.order[0]]
	assert.Equal(t, report.CodeUnknownEcosystem, d.Code)
	assert.Equal(t, "vet has no data for the git ecosystem, so it skips its packages", d.Message)
	assert.Equal(t, 2, d.Count)
}
