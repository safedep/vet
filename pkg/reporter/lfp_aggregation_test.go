package reporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAggregateLFPMessages(t *testing.T) {
	t.Run("http and https urls are aggregated", func(t *testing.T) {
		groups := aggregateLFPMessages([]string{
			"Package `ok` resolved to an untrusted host `https://my-registry.internal/ok/-/ok-1.0.0.tgz`",
		})
		assert.Len(t, groups, 1)
		assert.Equal(t, "https://my-registry.internal/ok/-/ok-1.0.0.tgz", groups[0].url)
		assert.Equal(t, []string{"ok"}, groups[0].pkgOrder)
	})

	// Regression: non-http(s) schemes (git deps) must not be silently dropped.
	// Previously lfpURLRe only matched http(s), so these findings disappeared and
	// the "Lockfile Poisoning Detected" section rendered empty.
	t.Run("git scheme urls are not dropped", func(t *testing.T) {
		cases := []struct {
			name string
			msg  string
			url  string
		}{
			{"git+ssh", "Package `glob` resolved to an untrusted host `git+ssh://git@github.com/isaacs/node-glob.git#abc`", "git+ssh://git@github.com/isaacs/node-glob.git#abc"},
			{"git+https", "Package `foo` resolved to an untrusted host `git+https://github.com/u/foo.git#deadbeef`", "git+https://github.com/u/foo.git#deadbeef"},
			{"git", "Package `bar` resolved to an untrusted host `git://github.com/u/bar.git`", "git://github.com/u/bar.git"},
			{"ssh", "Package `baz` resolved to an untrusted host `ssh://git@github.com/u/baz.git`", "ssh://git@github.com/u/baz.git"},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				groups := aggregateLFPMessages([]string{c.msg})
				assert.Len(t, groups, 1)
				assert.Equal(t, c.url, groups[0].url)
			})
		}
	})

	t.Run("path convention flag is detected", func(t *testing.T) {
		groups := aggregateLFPMessages([]string{
			"Package `foo` resolved to an URL `git+ssh://git@github.com/u/foo.git#x` that does not follow the package name path convention",
		})
		assert.Len(t, groups, 1)
		assert.True(t, groups[0].doesNotFollowPathConvention)
	})

	t.Run("same url across signals is aggregated into one group", func(t *testing.T) {
		url := "git+ssh://git@github.com/u/foo.git#x"
		groups := aggregateLFPMessages([]string{
			"Package `foo` resolved to an untrusted host `" + url + "`",
			"Package `foo` resolved to an URL `" + url + "` that does not follow the package name path convention",
		})
		assert.Len(t, groups, 1)
		assert.Equal(t, []string{"foo"}, groups[0].pkgOrder)
		assert.True(t, groups[0].doesNotFollowPathConvention)
	})
}
