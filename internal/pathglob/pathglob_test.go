package pathglob

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"test/fixtures", "test/fixtures/a/b.js", true},
		{"test/fixtures/", "test/fixtures/a.js", true},
		{"*.min.js", "dist/app.min.js", true},
		{"test/*/x.js", "test/a/x.js", true},
		{"src/app.js", "src/app.js", true},
		{"test/fixtures", "test/fixtures-old/a.js", false},
		{"test", "src/test.js", false},
		{"*.js", "src/a.ts", false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, Match(tc.pattern, tc.path), "%s %s", tc.pattern, tc.path)
	}
	assert.True(t, Valid("test/*"))
	assert.False(t, Valid("test/["))
}
