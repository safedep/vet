package extractors

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
)

// zipOf returns a zip archive with the files.
func zipOf(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, data := range files {
		f, err := w.Create(name)
		require.NoError(t, err)
		_, err = f.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return b.Bytes()
}

func pomProperties(group, artifact, version string) []byte {
	return []byte("groupId=" + group + "\nartifactId=" + artifact + "\nversion=" + version + "\n")
}

// TestJavaArchives checks that Scalibr's java/archive reads what the v1
// syft cataloger read: the pom.properties of a JAR, and the JARs inside a
// WAR (task 3.5).
func TestJavaArchives(t *testing.T) {
	root := t.TempDir()
	lib := zipOf(t, map[string][]byte{
		"META-INF/MANIFEST.MF":                          []byte("Manifest-Version: 1.0\n"),
		"META-INF/maven/com.example/lib/pom.properties": pomProperties("com.example", "lib", "1.2.3"),
	})
	inner := zipOf(t, map[string][]byte{
		"META-INF/maven/org.acme/inner/pom.properties": pomProperties("org.acme", "inner", "2.0.0"),
	})
	war := zipOf(t, map[string][]byte{
		"WEB-INF/web.xml":             []byte("<web-app/>"),
		"WEB-INF/lib/inner-2.0.0.jar": inner,
	})
	require.NoError(t, os.WriteFile(filepath.Join(root, "lib.jar"), lib, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app.war"), war, 0o600))

	exs, err := Default()
	require.NoError(t, err)

	cases := []struct {
		file string
		want string
	}{
		{"lib.jar", "maven/com.example:lib@1.2.3"},
		{"app.war", "maven/org.acme:inner@2.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			ms, errs := scalibr.ExtractFile(context.Background(), scalibr.File{Root: root, Path: tc.file}, exs)
			require.Empty(t, errs)
			require.Len(t, ms, 1)
			assert.Equal(t, "java/archive", ms[0].Extractor)
			var got []string
			for _, p := range ms[0].Packages {
				got = append(got, p.ID.String())
			}
			assert.Contains(t, got, tc.want)
		})
	}
}
