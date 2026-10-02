package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/plugin"
)

func TestContinueAfterInterrupt(t *testing.T) {
	f := newFixture(t)
	dir := project(t)
	stopped := interrupt(t, f, dir)

	// Between the runs one file changes and one goes.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.32.0\n"), 0o600))
	require.NoError(t, os.Remove(filepath.Join(dir, "vendor", "requirements.txt")))

	en := &fakeEnricher{}
	o := f.options(t, dir, en)
	o.Cache = nil
	res := runScan(t, o)

	assert.True(t, res.Continued)
	assert.Equal(t, stopped.ID, res.Entry.ID, "the same scan id")
	assert.True(t, res.Entry.Continued)
	assert.True(t, res.Scan.Header().Scan.Continued)
	assert.Equal(t, state.StatusCompleted, res.Entry.Status)
	assert.Equal(t, 2, en.seen, "the saved package is not enriched again, the new requests version is")

	var got []string
	for p, err := range res.Scan.Packages(context.Background(), plugin.PackageQuery{}) {
		require.NoError(t, err)
		got = append(got, p.ID.String())
	}
	assert.ElementsMatch(t, []string{"npm/left-pad@1.3.0", "npm/evil@1.0.0", "pypi/requests@2.32.0"}, got)
}

func TestContinueRules(t *testing.T) {
	cases := []struct {
		name      string
		fresh     bool
		resume    bool
		age       time.Duration
		continues bool
	}{
		{name: "no flag continues", continues: true},
		{name: "fresh starts a new scan", fresh: true},
		{name: "old scan starts a new scan", age: 48 * time.Hour},
		{name: "resume continues an old scan", age: 48 * time.Hour, resume: true, continues: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			dir := project(t)
			stopped := interrupt(t, f, dir)

			o := f.options(t, dir, &fakeEnricher{})
			o.Fresh, o.Resume = tc.fresh, tc.resume
			o.Now = func() time.Time { return time.Now().Add(tc.age) }
			res := runScan(t, o)
			assert.Equal(t, tc.continues, res.Continued)
			assert.Equal(t, tc.continues, res.Entry.ID == stopped.ID)
			if !tc.continues {
				require.NotNil(t, res.NotContinued)
				assert.NotEmpty(t, res.NotContinued.Reason)
			}
		})
	}
}

func TestResumeWithNothingToResume(t *testing.T) {
	f := newFixture(t)
	o := f.options(t, project(t), &fakeEnricher{})
	o.Resume = true
	_, err := Run(context.Background(), o)
	require.Error(t, err)
	assert.Equal(t, app.ExitUsage, app.ExitCode(err))
	assert.Contains(t, err.Error(), "no stopped scan")
}
