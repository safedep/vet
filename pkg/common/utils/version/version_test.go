package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolve(t *testing.T) {
	cases := []struct {
		name     string
		expr     string
		expected string
	}{
		{"Exact release", "4.17.21", "4.17.21"},
		{"Single component release", "3", "3"},
		{"Python prerelease", "1.0.0rc1", "1.0.0rc1"},
		{"Tag with a v prefix", "v1.2.3", "v1.2.3"},
		{"Semver with prerelease and build", "1.0.0-beta.1+build.7", "1.0.0-beta.1+build.7"},
		{"Maven snapshot", "1.1.0-SNAPSHOT", "1.1.0-SNAPSHOT"},
		{"Maven classifier", "9.4.53.v20231009", "9.4.53.v20231009"},
		{"Go pseudo version", "0.0.0-20221118182256-c68fdcfa2092", "0.0.0-20221118182256-c68fdcfa2092"},
		{"Git ref", "main", "main"},
		{"Git commit", "a09933a12a80f87b87005513f0abb1494c27a716", "a09933a12a80f87b87005513f0abb1494c27a716"},
		{"Dist tag", "latest", "latest"},

		{"Equals operator", "==3.0.0", "3.0.0"},
		{"Equals operator with a space", "== 3.0.0", "3.0.0"},
		{"Single equals operator", "=1.2.3", "1.2.3"},

		{"Empty expression", "", ""},
		{"Whitespace only", "   ", ""},
		{"Greater or equal", ">=2.28", ""},
		{"Compatible release", "~=4.2", ""},
		{"Not equal", "!=2.0", ""},
		{"Caret range", "^4.0.0", ""},
		{"Tilde range", "~4.0.0", ""},
		{"Wildcard", "*", ""},
		{"Partial wildcard", "4.*", ""},
		{"Two clauses", ">= 2.8.0,<= 6.2.5", ""},
		{"Alternative clauses", ">= 1.5.6,< 1.5.7 || > 1.5.7", ""},
		{"Maven range", "[1.0,2.0)", ""},
		{"Operator without an operand", ">=", ""},
		{"Equals without an operand", "==", ""},
		{"SPDX no assertion", "NOASSERTION", ""},
		{"SPDX none", "NONE", ""},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, Resolve(test.expr))
		})
	}
}
