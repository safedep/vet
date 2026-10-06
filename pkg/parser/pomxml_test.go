package parser

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func Test_MavenPomXmlParser_UpstreamRegistry(t *testing.T) {
	// Fake private registry with internal artifacts that Maven Central does not have.
	// lib depends on util, so a pass proves transitive lookups also use the registry.
	poms := map[string]string{
		"/maven/io/safedep/internal/lib/1.0/lib-1.0.pom": `<project>
  <groupId>io.safedep.internal</groupId><artifactId>lib</artifactId><version>1.0</version>
  <dependencies>
    <dependency><groupId>io.safedep.internal</groupId><artifactId>util</artifactId><version>2.0</version></dependency>
  </dependencies>
</project>`,
		"/maven/io/safedep/internal/util/2.0/util-2.0.pom": `<project>
  <groupId>io.safedep.internal</groupId><artifactId>util</artifactId><version>2.0</version>
</project>`,
	}

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := poms[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	// No <repositories> block: the registry must come from the parser config
	pomPath := filepath.Join(t.TempDir(), "pom.xml")
	err := os.WriteFile(pomPath, []byte(`<project>
  <groupId>io.safedep.test</groupId><artifactId>app</artifactId><version>1.0</version>
  <dependencies>
    <dependency><groupId>io.safedep.internal</groupId><artifactId>lib</artifactId><version>1.0</version></dependency>
  </dependencies>
</project>`), 0o600)
	require.NoError(t, err)

	manifest, err := parseMavenPomXmlFile(pomPath, &ParserConfig{
		MavenUpstreamRegistry: server.URL + "/maven",
	})
	require.NoError(t, err)

	names := []string{}
	for _, pkg := range manifest.Packages {
		names = append(names, pkg.Name)
	}

	assert.ElementsMatch(t, []string{"io.safedep.internal:lib", "io.safedep.internal:util"}, names)
	assert.Equal(t, int32(2), hits.Load())
}

func Test_MavenPomXmlParser_UpstreamRegistryAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "ci-bot" || pass != "s3cret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="maven"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`<project>
  <groupId>io.safedep.internal</groupId><artifactId>lib</artifactId><version>1.0</version>
</project>`))
	}))
	defer server.Close()

	// The scalibr Maven client reads credentials from ${HOME}/.m2/settings.xml
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("VET_TEST_MAVEN_PASSWORD", "s3cret")
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".m2"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".m2", "settings.xml"), []byte(`<settings><servers>
  <server><id>acme-artifactory</id><username>ci-bot</username><password>${env.VET_TEST_MAVEN_PASSWORD}</password></server>
</servers></settings>`), 0o600))

	pomPath := filepath.Join(t.TempDir(), "pom.xml")
	require.NoError(t, os.WriteFile(pomPath, []byte(`<project>
  <groupId>io.safedep.test</groupId><artifactId>app</artifactId><version>1.0</version>
  <dependencies>
    <dependency><groupId>io.safedep.internal</groupId><artifactId>lib</artifactId><version>1.0</version></dependency>
  </dependencies>
</project>`), 0o600))

	t.Run("matching registry ID sends credentials", func(t *testing.T) {
		manifest, err := parseMavenPomXmlFile(pomPath, &ParserConfig{
			MavenUpstreamRegistry:   server.URL,
			MavenUpstreamRegistryID: "acme-artifactory",
		})
		require.NoError(t, err)
		require.Len(t, manifest.Packages, 1)
		assert.Equal(t, "io.safedep.internal:lib", manifest.Packages[0].Name)
	})

	t.Run("no registry ID sends no credentials", func(t *testing.T) {
		_, err := parseMavenPomXmlFile(pomPath, &ParserConfig{
			MavenUpstreamRegistry: server.URL,
		})
		assert.ErrorContains(t, err, "failed to fetch Maven project")
	})
}

func Test_MavenPomXmlParser_InvalidUpstreamRegistry(t *testing.T) {
	for _, registry := range []string{"not a url", "ftp://example.com/maven", "/relative/path", "https://"} {
		t.Run(registry, func(t *testing.T) {
			_, err := parseMavenPomXmlFile("./fixtures/java/pom.xml", &ParserConfig{
				MavenUpstreamRegistry: registry,
			})
			assert.ErrorContains(t, err, "invalid Maven upstream registry")
		})
	}

	t.Run("registry ID without registry URL", func(t *testing.T) {
		_, err := parseMavenPomXmlFile("./fixtures/java/pom.xml", &ParserConfig{
			MavenUpstreamRegistryID: "acme-artifactory",
		})
		assert.ErrorContains(t, err, "needs a Maven upstream registry URL")
	})
}

func Test_ValidateMavenUpstreamRegistry_Valid(t *testing.T) {
	for _, registry := range []string{
		"",
		"http://localhost:8081/repository/maven-public",
		"https://artifactory.example.com/maven",
		"artifactregistry://us-maven.pkg.dev/project/repo",
	} {
		assert.NoError(t, ValidateMavenUpstreamRegistry(registry, ""), registry)
	}
}
