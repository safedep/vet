package doctor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReleaseCheck(t *testing.T) {
	tags := []string{
		"v2.0.0-alpha.20261004163722",
		"v2.0.0-alpha.20261003120000",
		"v1.19.1",
		"v1.18.0",
		"v1.20.0-rc.1",
	}
	cases := []struct {
		name, current string
		tags          []string
		want          Status
		message       string
	}{
		{"an older v1", "v1.18.0", tags, Warn, "the newest release is v1.19.1, this is v1.18.0"},
		{"the newest v1", "v1.19.1", tags, Pass, "vet v1.19.1 is the newest release"},
		{"a v1 release build with no v", "1.19.1", tags, Pass, "vet 1.19.1 is the newest release"},
		{"the newest alpha with no v", "2.0.0-alpha.20261004163722", tags, Pass, "vet 2.0.0-alpha.20261004163722 is the newest release"},
		{"an older alpha", "2.0.0-alpha.20261003120000", tags, Warn, "the newest release is v2.0.0-alpha.20261004163722, this is 2.0.0-alpha.20261003120000"},
		{"a v2 release with no v2 release yet", "2.0.0", tags, Pass, "vet 2.0.0 has no newer release"},
		{"a v2 development build", "v2.0.0-20261002155234-310d5116f0dd", tags, Pass, "vet dev (310d511) is a development build"},
		{"a build with no version", "dev", tags, Warn, "the newest release is v1.19.1, this is dev"},
		{"no releases", "2.0.0-alpha.20261004163722", nil, Pass, "vet 2.0.0-alpha.20261004163722 has no newer release"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := releaseCheck(tc.tags, tc.current)
			assert.Equal(t, tc.want, c.Status)
			assert.Equal(t, tc.message, c.Message)
		})
	}
}
