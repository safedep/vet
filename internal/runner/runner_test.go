package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
