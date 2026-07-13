package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var deps = []string{
	"org.junit.jupiter:junit-jupiter-api",       // Direct
	"org.apiguardian:apiguardian-api",           // Transitive
	"org.junit.platform:junit-platform-commons", // Transitive
	"org.opentest4j:opentest4j",                 // Transitive
}

// skipIfMavenRegistryUnavailable skips a test that depends on resolving
// dependencies live from Maven Central when the registry is unreachable or
// rate-limits the request (HTTP 429). CI runners share egress IPs that are
// frequently rate-limited by Maven Central - an external, non-deterministic
// condition unrelated to the code under test. Any other error still fails the
// test so genuine parsing/resolution regressions are caught.
func skipIfMavenRegistryUnavailable(t *testing.T, err error) {
	t.Helper()

	msg := err.Error()
	for _, signal := range []string{
		"failed to fetch Maven project",     // resolver could not retrieve a POM
		"failed to load parent from remote", // remote parent fetch failed
		"Maven registry query",              // wraps non-200 (e.g. 429) and transport errors
	} {
		if strings.Contains(msg, signal) {
			t.Skipf("skipping: Maven registry unavailable or rate-limited: %v", err)
		}
	}
}

func Test_MavenPomXmlParser_Simple(t *testing.T) {
	manifest, err := parseMavenPomXmlFile("./fixtures/java/pom.xml", &ParserConfig{})
	if err != nil {
		skipIfMavenRegistryUnavailable(t, err)
		t.Fatal(err)
	}

	assert.Equal(t, len(manifest.Packages), 4) // total 4 deps
	for _, pkg := range manifest.Packages {
		assert.Contains(t, deps, pkg.Name)
	}
}

func Test_MavenPomXmlParser_ChildParentRelation(t *testing.T) {
	// child/pom.xml references parent/pom.xml using:
	// 	<relativePath>../parent/pom.xml</relativePath>
	manifest, err := parseMavenPomXmlFile("./fixtures/java/child/pom.xml", &ParserConfig{})
	if err != nil {
		skipIfMavenRegistryUnavailable(t, err)
		t.Fatal(err)
	}

	assert.Equal(t, len(manifest.Packages), 4)
	for _, pkg := range manifest.Packages {
		assert.Contains(t, deps, pkg.Name)
	}
}

func Test_MavenPomXmlParser_RemoteParent(t *testing.T) {
	manifest, err := parseMavenPomXmlFile("./fixtures/java/remote/pom.xml", &ParserConfig{})
	if err != nil {
		skipIfMavenRegistryUnavailable(t, err)
		t.Fatal(err)
	}

	assert.Equal(t, len(manifest.Packages), 4)
	for _, pkg := range manifest.Packages {
		assert.Contains(t, deps, pkg.Name)
	}
}
