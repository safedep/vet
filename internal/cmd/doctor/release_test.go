package doctor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReleaseCheck(t *testing.T) {
	cases := []struct {
		name, latest, current string
		want                  Status
	}{
		{"an older vet", "v1.19.1", "v1.18.0", Warn},
		{"the latest release", "v1.19.1", "v1.19.1", Pass},
		{"a v2 development build", "v1.19.1", "v2.0.0-20261002155234-310d5116f0dd", Pass},
		{"a build with no version", "v1.19.1", "dev", Warn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, releaseCheck(tc.latest, tc.current).Status)
		})
	}
}
