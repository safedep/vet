package yarnlock

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolvedURL(t *testing.T) {
	cases := map[string]string{
		"https://registry.yarnpkg.com/debug/-/debug-4.3.4.tgz#abc": "https://registry.yarnpkg.com/debug/-/debug-4.3.4.tgz#abc",
		"debug@npm:4.3.4":                                  "",
		"@scope/pkg@npm:1.0.0":                             "",
		"pkg@https://evil.example/pkg.tgz":                 "https://evil.example/pkg.tgz",
		"@scope/pkg@https://github.com/o/r.git#commit=abc": "https://github.com/o/r.git#commit=abc",
		"git+ssh://git@github.com:o/r#abc":                 "git+ssh://git@github.com:o/r#abc",
		"":                                                 "",
	}
	for in, want := range cases {
		assert.Equal(t, want, resolvedURL(in), in)
	}
}
