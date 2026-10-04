package hygiene

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProjectRoot(t *testing.T) {
	cases := map[string]bool{
		"file:.":            true,
		"-e .":              true,
		"-e .[socks]":       true,
		".[dev,test]":       true,
		"./":                true,
		"file:../shared":    false,
		"-e ./packages/lib": false,
		"git+https://x/y":   false,
	}
	for in, want := range cases {
		assert.Equal(t, want, projectRoot(in), in)
		if want {
			assert.Empty(t, nonRegistrySource(in), in)
		}
	}
}
