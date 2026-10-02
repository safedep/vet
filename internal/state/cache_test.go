package state

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
)

func pkg(name string) *model.Package {
	return &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: name, Version: "1.0.0"}}
}

func TestCache(t *testing.T) {
	ctx := context.Background()
	c, err := OpenCache(ctx, t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }

	a, b, failed := pkg("a"), pkg("b"), pkg("f")
	a.Insight = &model.Insight{Licenses: []string{"MIT"}}
	require.NoError(t, c.Put(ctx, "1", time.Hour, []EnrichmentResult{
		{Package: a, Enricher: "insights", Status: EnrichmentOK},
		{Package: b, Enricher: "insights", Status: EnrichmentNotFound},
		{Package: failed, Enricher: "insights", Status: EnrichmentFailed},
	}))

	cases := []struct {
		name    string
		version string
		after   time.Duration
		hits    []string
	}{
		{name: "live entries hit", version: "1", hits: []string{"a", "b"}},
		{name: "another enricher version misses", version: "2"},
		{name: "expired entries miss", version: "1", after: 2 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c.now = func() time.Time { return now.Add(tc.after) }
			pa, pb, pf := pkg("a"), pkg("b"), pkg("f")
			hits, misses, err := c.Lookup(ctx, "insights", tc.version, []*model.Package{pa, pb, pf})
			require.NoError(t, err)
			var names []string
			for _, h := range hits {
				names = append(names, h.Package.ID.Name)
			}
			assert.Equal(t, tc.hits, names)
			assert.Len(t, misses, 3-len(tc.hits))
			if len(tc.hits) > 0 {
				require.NotNil(t, pa.Insight)
				assert.Equal(t, []string{"MIT"}, pa.Insight.Licenses)
				assert.Equal(t, EnrichmentNotFound, hits[1].Status)
			}
		})
	}

	c.now = func() time.Time { return now.Add(2 * time.Hour) }
	n, err := c.Prune(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)
}
