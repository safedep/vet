package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/engine"
)

func TestLockableKeys(t *testing.T) {
	cases := []struct {
		name string
		o    Options
		want []string
	}{
		{"no flag", Options{}, nil},
		{"gate", Options{FailOn: "high", Policy: "p.yml"}, []string{"policy.fail_on", "policy.file"}},
		{
			"scan flags",
			Options{Strict: true, Exclude: []string{"docs"}, CooldownDays: 7},
			[]string{"scan.strict", "scan.exclude", "plugins.dependency-cooldown.options.days"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.o.lockableKeys())
		})
	}
}

func TestOutcome(t *testing.T) {
	cases := []struct {
		name              string
		renderErr, runErr error
		want              int
	}{
		{"clean", nil, nil, app.ExitOK},
		{"gate", app.ErrGateFailed, nil, app.ExitGateFailed},
		{"strict", nil, engine.ErrStrict, app.ExitRuntime},
		{"strict and gate", app.ErrGateFailed, engine.ErrStrict, app.ExitRuntime},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := outcome(tc.renderErr, tc.runErr)
			assert.Equal(t, tc.want, app.ExitCode(err))
			if tc.runErr != nil {
				assert.ErrorContains(t, err, CodeStrict, "the strict message prints")
			}
		})
	}
}
