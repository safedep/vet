package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveParseTarget(t *testing.T) {
	cases := []struct {
		name       string
		scopes     []TargetScopeType
		path       string
		lockfileAs string
		outputPath string
		outputType string
		err        error
	}{
		{
			"Explicit type",
			[]TargetScopeType{TargetScopeAll},
			"/a/b/c.txt",
			"requirements.txt",
			"/a/b/c.txt",
			"requirements.txt",
			nil,
		},
		{
			"Explicit type overrides everything else",
			[]TargetScopeType{TargetScopeAll},
			"jar:/a/b/c.jar",
			"requirements.txt",
			"jar:/a/b/c.jar",
			"requirements.txt",
			nil,
		},
		{
			"Path with embedded type",
			[]TargetScopeType{TargetScopeAll},
			"requirements.txt:/a/b/c.txt",
			"",
			"/a/b/c.txt",
			"requirements.txt",
			nil,
		},
		{
			"Loosely embedded type in path",
			[]TargetScopeType{TargetScopeAll},
			"requirements.txt:/a/b/c.txt:aa",
			"",
			"requirements.txt:/a/b/c.txt:aa",
			"",

			// We do not error out because our parsers can resolve from file name
			nil,
		},
		{
			"Path with mapped extension",
			[]TargetScopeType{TargetScopeAll},
			"/a/b/c.jar",
			"",
			"/a/b/c.jar",
			"jar",
			nil,
		},
		{
			"Path with unmapped extension",
			[]TargetScopeType{TargetScopeAll},
			"/a/b/c.py",
			"",
			"/a/b/c.py",
			"",
			nil,
		},
		{
			"Path with mapped extension is not resolved when scope is not allowed",
			[]TargetScopeType{},
			"/a/b/c.jar",
			"",
			"/a/b/c.jar",
			"",
			nil,
		},
		{
			"Path with embedded type is not resolved when scope is not allowed",
			[]TargetScopeType{},
			"requirements.txt:/a/b/c.txt",
			"",
			"requirements.txt:/a/b/c.txt",
			"",
			nil,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			path, lft, err := ResolveParseTarget(test.path, test.lockfileAs, test.scopes)
			if test.err != nil {
				assert.ErrorContains(t, err, test.err.Error())
			} else {
				assert.Nil(t, err)
				assert.Equal(t, test.outputPath, path)
				assert.Equal(t, test.outputType, lft)
			}
		})
	}
}
