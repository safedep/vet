package terraform

import (
	"context"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
)

func TestExtract(t *testing.T) {
	ms, errs := scalibr.ExtractFile(context.Background(),
		scalibr.File{Root: "testdata", Path: ".terraform.lock.hcl"}, []filesystem.Extractor{New()})
	require.Empty(t, errs)
	require.Len(t, ms, 1)
	m := ms[0]
	assert.Equal(t, "terraform", string(m.Ecosystem))
	require.NotEmpty(t, m.Packages)
	p := m.Packages[0]
	assert.Equal(t, "registry.terraform.io/datadog/datadog", p.ID.QualifiedName())
	assert.Equal(t, "3.21.0", p.ID.Version)
	assert.Equal(t, 1, p.Line)
	assert.True(t, p.Direct)
	t.Log(p.ID.PURL())
}
