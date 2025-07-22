package readers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExcludedPath(t *testing.T) {
	cases := []struct {
		name             string
		path             string
		patterns         []string
		shouldBeExcluded bool
	}{
		{
			name:             "No exclusions",
			path:             "package-lock.json",
			patterns:         []string{},
			shouldBeExcluded: false,
		},
		{
			name:             "Simple glob match",
			path:             "vendor/package-lock.json",
			patterns:         []string{"vendor/*"},
			shouldBeExcluded: true,
		},
		{
			name: "Multiple patterns with match",
			path: "test/yarn.lock",
			patterns: []string{
				"vendor/*",
				"test/*",
				"node_modules/*",
			},
			shouldBeExcluded: true,
		},
		{
			name: "Multiple patterns without match",
			path: "src/package-lock.json",
			patterns: []string{
				"vendor/*",
				"test/*",
				"node_modules/*",
			},
			shouldBeExcluded: false,
		},
		{
			name:             "Invalid pattern character",
			path:             "package-lock.json",
			patterns:         []string{"["},
			shouldBeExcluded: false,
		},
		{
			name:             "Subdirectory with match",
			path:             "pkg/readers/fixtures/requirements.txt",
			patterns:         []string{"pkg/readers/*/**"},
			shouldBeExcluded: true,
		},
		{
			name:             "Subdirectory without match",
			path:             "pkg/readers/fixtures/requirements.txt",
			patterns:         []string{"pkg/readers/*"},
			shouldBeExcluded: false,
		},
		{
			name:             "Single character wildcard",
			path:             "test/a.json",
			patterns:         []string{"test/?.json"},
			shouldBeExcluded: true,
		},
		{
			name:             "Character class match",
			path:             "test-123/package.json",
			patterns:         []string{"test-[0-9]*/package.json"},
			shouldBeExcluded: true,
		},
		{
			name:             "matches wildcard with missing characters in filename",
			path:             "pom.xml",
			patterns:         []string{"p*.xml"},
			shouldBeExcluded: true,
		},
		{
			name:             "matches wildcard across nested subdirectories",
			path:             "pkg/readers/fixtures/requirements.txt",
			patterns:         []string{"pkg/readers/**/*.txt"},
			shouldBeExcluded: true,
		},
		{
			name:             "should exclude deeply nested file with recursive glob",
			path:             "dir1/subdirA/subdirB/requirements.txt",
			patterns:         []string{"**/requirements.txt"},
			shouldBeExcluded: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matcher := newPathExclusionMatcher(tc.patterns)
			result := matcher.Match(tc.path)
			assert.Equal(t, tc.shouldBeExcluded, result,
				"Expected path.Match to return %v for path %s with patterns %v",
				tc.shouldBeExcluded, tc.path, tc.patterns)
		})
	}
}
