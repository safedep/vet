package parser

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var deps = []string{
	"org.junit.jupiter:junit-jupiter-api",       // Direct
	"org.apiguardian:apiguardian-api",           // Transitive
	"org.junit.platform:junit-platform-commons", // Transitive
	"org.opentest4j:opentest4j",                 // Transitive
}

func Test_MavenPomXmlParser_Simple(t *testing.T) {
	manifest, err := parseMavenPomXmlFile("./fixtures/java/pom.xml", &ParserConfig{})
	if err != nil {
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
		t.Fatal(err)
	}

	assert.Equal(t, len(manifest.Packages), 4)
	for _, pkg := range manifest.Packages {
		assert.Contains(t, deps, pkg.Name)
	}
}
