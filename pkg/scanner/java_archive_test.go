package scanner

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/vet/ent"
	"github.com/safedep/vet/pkg/code"
	"github.com/safedep/vet/pkg/common/purl"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/storage"
	"github.com/stretchr/testify/require"
)

// TestJavaArchiveMatchesOnlyClassesInArtifact checks supported Java import
// forms and rejects unrelated packages, source types, and wildcard scopes.
func TestJavaArchiveMatchesOnlyClassesInArtifact(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "commons-lang3.jar")
	file, err := os.Create(archivePath)
	require.NoError(t, err)
	writer := zip.NewWriter(file)
	for _, name := range []string{
		"META-INF/maven/org.apache.commons/commons-lang3/pom.properties",
		"org/apache/commons/lang3/StringUtils.class",
		"org/apache/commons/lang3/Outer$Inner.class",
		"org/apache/commons/lang3/math/NumberUtils.class",
	} {
		_, err := writer.Create(name)
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	require.NoError(t, file.Close())

	index, err := indexJavaArchive(archivePath)
	require.NoError(t, err)
	for _, tc := range []struct {
		module   string
		wildcard bool
		path     string
		want     bool
	}{
		{"org.apache.commons.lang3.StringUtils", false, "src/App.java", true},
		{"org.apache.commons.lang3.StringUtils.isBlank", false, "src/App.java", true},
		{"org.apache.commons.lang3.StringUtils", true, "src/App.java", true},
		{"org.apache.commons.lang3.Outer.Inner", false, "src/App.java", true},
		{"org.apache.commons.lang3", true, "src/App.java", true},
		{"org.apache.commons.lang3.math", true, "src/App.java", true},
		{"org.apache.commons", true, "src/App.java", false},
		{"org.apache.commons.lang3.text.WordUtils", false, "src/App.java", false},
		{"org.apache.commons.text.StringEscapeUtils", false, "src/App.java", false},
		{"org.apache.commons.lang3.StringUtils", false, "src/App.py", false},
	} {
		evidence := &ent.DepsUsageEvidence{ModuleName: tc.module, IsWildCardUsage: tc.wildcard, UsageFilePath: tc.path}
		require.Equal(t, tc.want, index.containsJavaImport(evidence), tc.module)
	}
}

// TestLocalJavaArchives checks exact Maven and Gradle cache locations and
// rejects coordinate values that could escape those cache paths.
func TestLocalJavaArchives(t *testing.T) {
	root := t.TempDir()
	mavenRoot := filepath.Join(root, "maven")
	gradleRoot := filepath.Join(root, "gradle")
	t.Setenv("MAVEN_REPO_LOCAL", mavenRoot)
	t.Setenv("GRADLE_USER_HOME", gradleRoot)

	mavenJar := filepath.Join(mavenRoot, "org", "apache", "commons", "commons-lang3", "3.17.0", "commons-lang3-3.17.0.jar")
	gradleJar := filepath.Join(gradleRoot, "caches", "modules-2", "files-2.1", "org.apache.commons", "commons-lang3", "3.17.0", "digest", "commons-lang3-3.17.0.jar")
	for _, path := range []string{mavenJar, gradleJar} {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, nil, 0o644))
	}
	require.ElementsMatch(t, []string{mavenJar, gradleJar}, localJavaArchives("org.apache.commons", "commons-lang3", "3.17.0"))
	require.Empty(t, localJavaArchives("org.apache.commons", "../other", "3.17.0"))
	require.Empty(t, localJavaArchives("org.apache.commons", "commons-lang3", "../3.17.0"))
}

// TestCodeAnalysisEnricherMatchesJavaImportsToMavenArchive exercises evidence
// enrichment through the code database for Maven and CycloneDX packages.
func TestCodeAnalysisEnricherMatchesJavaImportsToMavenArchive(t *testing.T) {
	root := t.TempDir()
	t.Setenv("MAVEN_REPO_LOCAL", filepath.Join(root, "maven"))
	t.Setenv("GRADLE_USER_HOME", filepath.Join(root, "gradle"))
	jar := filepath.Join(root, "maven", "org", "apache", "commons", "commons-lang3", "3.17.0", "commons-lang3-3.17.0.jar")
	require.NoError(t, os.MkdirAll(filepath.Dir(jar), 0o755))
	createTestJavaArchive(t, jar, "org/apache/commons/lang3/StringUtils.class")

	db, err := storage.NewEntSqliteStorage(storage.EntSqliteClientConfig{Path: filepath.Join(root, "code.db")})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	client, err := db.Client()
	require.NoError(t, err)
	source, err := client.CodeSourceFile.Create().SetPath("src/App.java").Save(context.Background())
	require.NoError(t, err)
	_, err = client.DepsUsageEvidence.Create().
		SetPackageHint("").
		SetModuleName("org.apache.commons.lang3.StringUtils").
		SetUsageFilePath("src/App.java").
		SetLine(3).
		SetUsedIn(source).
		Save(context.Background())
	require.NoError(t, err)

	repository, err := code.NewReaderRepository(client)
	require.NoError(t, err)
	enricher := NewCodeAnalysisEnricher(CodeAnalysisEnricherConfig{EnableDepsUsageEvidence: true}, repository)
	used := &models.Package{PackageDetails: models.NewPackageDetail(models.EcosystemMaven, "org.apache.commons:commons-lang3", "3.17.0")}
	require.NoError(t, enricher.Enrich(used, nil))
	require.Len(t, used.CodeAnalysis.UsageEvidences, 1)
	require.Equal(t, "org.apache.commons.lang3.StringUtils", used.CodeAnalysis.UsageEvidences[0].ModuleName)

	badJar := filepath.Join(root, "maven", "org", "apache", "commons", "commons-text", "1.13.0", "commons-text-1.13.0.jar")
	require.NoError(t, os.MkdirAll(filepath.Dir(badJar), 0o755))
	require.NoError(t, os.WriteFile(badJar, []byte("not a jar"), 0o644))
	unused := &models.Package{PackageDetails: models.NewPackageDetail(models.EcosystemMaven, "org.apache.commons:commons-text", "1.13.0")}
	require.NoError(t, enricher.Enrich(unused, nil))
	require.Empty(t, unused.CodeAnalysis.UsageEvidences)

	// CycloneDX components use Maven package URLs. Their parsed coordinates
	// must follow the same enrichment path as a pom.xml dependency.
	parsed, err := purl.ParsePackageUrl("pkg:maven/org.apache.commons/commons-lang3@3.17.0?type=jar")
	require.NoError(t, err)
	fromSBOM := &models.Package{PackageDetails: parsed.GetPackageDetails()}
	require.NoError(t, enricher.Enrich(fromSBOM, nil))
	require.Len(t, fromSBOM.CodeAnalysis.UsageEvidences, 1)
}

// createTestJavaArchive writes only JAR entry names because archive matching
// never needs class bytecode.
func createTestJavaArchive(t *testing.T, path string, classes ...string) {
	t.Helper()
	file, err := os.Create(path)
	require.NoError(t, err)
	writer := zip.NewWriter(file)
	for _, class := range classes {
		_, err := writer.Create(class)
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	require.NoError(t, file.Close())
}
