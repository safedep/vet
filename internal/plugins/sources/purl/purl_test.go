package purl

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

func TestArtifactKeepsTheRawForm(t *testing.T) {
	cases := []struct {
		target, name, version string
	}{
		{"pkg:pypi/X@1.0.0.0.0.0", "X", "1.0.0.0.0.0"},
		{"pkg:golang/github.com/Masterminds/goutils@v1.1.0", "github.com/Masterminds/goutils", "v1.1.0"},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			var got []plugin.Artifact
			for a, err := range New(Options{Target: tc.target}).Artifacts(context.Background()) {
				require.NoError(t, err)
				got = append(got, a)
			}
			require.Len(t, got, 1)
			id, err := model.ParsePURL(got[0].PURL)
			require.NoError(t, err)
			assert.Equal(t, tc.name, id.RawName())
			assert.Equal(t, tc.version, id.RawVersion())
		})
	}
}

func TestSpellingsShareATargetKey(t *testing.T) {
	key := func(target string) string {
		for a, err := range New(Options{Target: target}).Artifacts(context.Background()) {
			require.NoError(t, err)
			return a.Key
		}
		return ""
	}
	assert.Equal(t, key("pkg:pypi/Zope.Interface@1.0.0.0"), key("pkg:pypi/zope-interface@1.0"))
}
