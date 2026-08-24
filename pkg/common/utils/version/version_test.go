package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var resolveCases = []struct {
	name     string
	expr     string
	expected string
}{
	{"Exact release", "4.17.21", "4.17.21"},
	{"Single component release", "3", "3"},
	{"Python prerelease", "1.0.0rc1", "1.0.0rc1"},
	{"Tag with a v prefix", "v1.2.3", "v1.2.3"},
	{"Semver with prerelease and build", "1.0.0-beta.1+build.7", "1.0.0-beta.1+build.7"},
	{"Major version branch", "2.x", "2.x"},
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
	{"Maven range", "[1.0,2.0)", ""},
	{"Operator without an operand", ">=", ""},
	{"Equals without an operand", "==", ""},
	{"SPDX no assertion", "NOASSERTION", ""},
	{"SPDX none", "NONE", ""},

	// Real strings from the SPDX fixtures in this repo.
	{"Two component release", "7.1", "7.1"},
	{"Four component release", "0.0.8.2", "0.0.8.2"},
	{"Maven snapshot", "1.1.0-SNAPSHOT", "1.1.0-SNAPSHOT"},
	{"Maven date qualifier", "9.4.53.v20231009", "9.4.53.v20231009"},
	{"Dash separated prerelease", "4.0.0-beta-01", "4.0.0-beta-01"},
	{"Go pseudo release", "0.0.0-20221118182256-c68fdcfa2092", "0.0.0-20221118182256-c68fdcfa2092"},
	{"Go pseudo release on a base", "1.5.1-0.20230307220236-3a3c6141e376", "1.5.1-0.20230307220236-3a3c6141e376"},
	{"Git ref", "main", "main"},
	{"Git commit", "a09933a12a80f87b87005513f0abb1494c27a716", "a09933a12a80f87b87005513f0abb1494c27a716"},
	{"Less than with a space", "< 40.0.0", ""},
	{"Two clauses", ">= 2.8.0,<= 6.2.5", ""},
	{"Alternative clauses", ">= 1.5.6,< 1.5.7 || > 1.5.7", ""},

	// Real strings from the CycloneDX fixtures in this repo.
	{"Maven final qualifier", "5.4.3.Final", "5.4.3.Final"},
	{"Maven candidate qualifier", "7.0.0.CR1", "7.0.0.CR1"},
	{"Numeric prerelease", "0.0.2-1", "0.0.2-1"},

	// Real strings from the lockfile fixtures in this repo.
	{"Git describe output", "v4.8.0-79-gd8fefc9", "v4.8.0-79-gd8fefc9"},
	{"Greater than", ">3.6.0", ""},
	{"Two clauses joined by a space", ">= 2.1.2 < 3", ""},
	{"Alternative caret ranges", "^5.0.0 || ^6.0.2 || ^7.0.0", ""},
}

func TestResolve(t *testing.T) {
	for _, test := range resolveCases {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, Resolve(test.expr))
		})
	}
}

// FuzzResolve guards three invariants: Resolve never panics, it never returns a
// value it did not read from the input, and a release resolves to itself.
func FuzzResolve(f *testing.F) {
	for _, test := range resolveCases {
		f.Add(test.expr)
	}

	f.Fuzz(func(t *testing.T, expr string) {
		release := Resolve(expr)

		if !strings.Contains(expr, release) {
			t.Fatalf("Resolve(%q) returned %q, which the input does not hold", expr, release)
		}

		if again := Resolve(release); again != release {
			t.Fatalf("Resolve(%q) returned %q, which resolves on to %q", expr, release, again)
		}
	})
}
