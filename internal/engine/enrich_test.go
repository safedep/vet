package engine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
)

func TestEnrichBatchSkipsUncheckable(t *testing.T) {
	id := func(version string) model.PackageID {
		return model.PackageID{Ecosystem: model.EcosystemPyPI, Name: "pkg-" + version, Version: version}
	}
	pkgs := []*model.Package{{ID: id("1.0.0")}, {ID: id("")}, {ID: id("2.0.0"), Local: true}}
	cases := []struct {
		name  string
		local bool
		want  int
	}{
		{"a registry enricher gets the versioned registry package", false, 1},
		{"a local enricher gets every package", true, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			en := &fakeEnricher{}
			r := &run{diags: &diagnostics{}}
			res, err := r.enrichBatch(context.Background(), Enricher{Name: "fake", Plugin: en, Local: tc.local}, pkgs)
			require.NoError(t, err)
			assert.Len(t, res, len(pkgs), "each package gets a result")
			assert.Equal(t, tc.want, en.seen)
		})
	}
}
