package code

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/safedep/code/core"
	"github.com/safedep/code/lang"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/pkg/storage"
	xbomsig "github.com/safedep/vet/pkg/xbom/signatures"
	_ "github.com/safedep/vet/signatures" // triggers embed registration
)

func getAllLanguageCodes() []string {
	langs, err := lang.AllLanguages()
	if err != nil {
		return nil
	}
	var codes []string
	for _, l := range langs {
		codes = append(codes, string(l.Meta().Code))
	}
	return codes
}

func languagesFromCodes(codes []string) ([]core.Language, error) {
	var languages []core.Language
	for _, code := range codes {
		language, err := lang.GetLanguage(code)
		if err != nil {
			return nil, err
		}
		languages = append(languages, language)
	}
	return languages, nil
}

type expectedMatch struct {
	signatureID string
	language    string
	matchedCall string
}

func TestScannerSignatureMatching(t *testing.T) {
	cases := []struct {
		name            string
		fixtureDir      string
		vendor          string
		expectedMatches []expectedMatch
		minMatchCount   int
	}{
		{
			name:       "Go capabilities detection",
			fixtureDir: "testdata/test_go_capabilities",
			vendor:     "lang/golang",
			expectedMatches: []expectedMatch{
				{signatureID: "golang.filesystem.write", language: "go", matchedCall: "os/WriteFile"},
				{signatureID: "golang.filesystem.read", language: "go", matchedCall: "os/ReadFile"},
				{signatureID: "golang.filesystem.delete", language: "go", matchedCall: "os/Remove"},
				{signatureID: "golang.filesystem.mkdir", language: "go", matchedCall: "os/Mkdir"},
				{signatureID: "golang.network.http.client", language: "go", matchedCall: "net/http/Get"},
				{signatureID: "golang.network.http.server", language: "go", matchedCall: "net/http/ListenAndServe"},
				{signatureID: "golang.process.exec", language: "go", matchedCall: "os/exec/Command"},
				{signatureID: "golang.process.info", language: "go", matchedCall: "os/Getpid"},
				{signatureID: "golang.environment.read", language: "go", matchedCall: "os/Getenv"},
				{signatureID: "golang.environment.write", language: "go", matchedCall: "os/Setenv"},
				{signatureID: "golang.crypto.hash", language: "go", matchedCall: "crypto/sha256/Sum256"},
				{signatureID: "golang.crypto.aes", language: "go", matchedCall: "crypto/aes/NewCipher"},
				{signatureID: "golang.database.sql", language: "go", matchedCall: "database/sql/Open"},
			},
			minMatchCount: 13,
		},
		{
			name:       "Python capabilities detection",
			fixtureDir: "testdata/test_python_capabilities",
			vendor:     "lang/python",
			expectedMatches: []expectedMatch{
				{signatureID: "python.filesystem.delete", language: "python", matchedCall: "os.remove"},
				{signatureID: "python.filesystem.mkdir", language: "python", matchedCall: "os.mkdir"},
				{signatureID: "python.network.http.client", language: "python", matchedCall: "urllib.request.urlopen"},
				{signatureID: "python.environment.read", language: "python", matchedCall: "os.getenv"},
				{signatureID: "python.process.exec", language: "python", matchedCall: "subprocess.run"},
				{signatureID: "python.process.info", language: "python", matchedCall: "os.getpid"},
				{signatureID: "python.database.sql", language: "python", matchedCall: "sqlite3.connect"},
			},
			minMatchCount: 7,
		},
		{
			name:       "JavaScript capabilities detection",
			fixtureDir: "testdata/test_javascript_capabilities",
			vendor:     "lang/javascript",
			expectedMatches: []expectedMatch{
				{signatureID: "javascript.filesystem.write", language: "javascript", matchedCall: "fs/writeFileSync"},
				{signatureID: "javascript.filesystem.read", language: "javascript", matchedCall: "fs/readFileSync"},
				{signatureID: "javascript.filesystem.delete", language: "javascript", matchedCall: "fs/unlinkSync"},
				{signatureID: "javascript.filesystem.mkdir", language: "javascript", matchedCall: "fs/mkdirSync"},
				{signatureID: "javascript.network.http.client", language: "javascript", matchedCall: "http/get"},
				{signatureID: "javascript.network.http.server", language: "javascript", matchedCall: "http/createServer"},
				{signatureID: "javascript.process.exec", language: "javascript", matchedCall: "child_process/exec"},
				{signatureID: "javascript.crypto.hash", language: "javascript", matchedCall: "crypto/createHash"},
				{signatureID: "javascript.database.sql", language: "javascript", matchedCall: "sqlite3/Database"},
			},
			minMatchCount: 9,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "test.db")

			// Load signatures for the specific language
			sigs, err := xbomsig.LoadSignatures(tc.vendor, "", "")
			require.NoError(t, err)
			require.NotEmpty(t, sigs)

			fixtureAbs, err := filepath.Abs(tc.fixtureDir)
			require.NoError(t, err)

			// Create storage
			entStorage, err := storage.NewEntSqliteStorage(storage.EntSqliteClientConfig{
				Path: dbPath,
			})
			require.NoError(t, err)

			// Resolve languages from the safedep/code library
			allLangCodes := getAllLanguageCodes()
			langs, err := languagesFromCodes(allLangCodes)
			require.NoError(t, err)

			// Create and run scanner
			scanner, err := NewScanner(ScannerConfig{
				AppDirectories:            []string{fixtureAbs},
				Languages:                 langs,
				SkipDependencyUsagePlugin: true,
				SkipSignatureMatching:     false,
				SignaturesToMatch:         sigs,
				Callbacks: &ScannerCallbackRegistry{
					OnScanStart: func() error { return nil },
					OnScanEnd:   func() error { return nil },
				},
			}, entStorage)
			require.NoError(t, err)

			err = scanner.Scan(context.Background())
			require.NoError(t, err)

			// Query the results from the DB
			client, err := entStorage.Client()
			require.NoError(t, err)

			reader, err := NewReaderRepository(client)
			require.NoError(t, err)

			allMatches, err := reader.GetAllSignatureMatches(context.Background())
			require.NoError(t, err)

			// Verify minimum match count
			assert.GreaterOrEqual(t, len(allMatches), tc.minMatchCount,
				"Expected at least %d matches, got %d", tc.minMatchCount, len(allMatches))

			// Build a lookup of actual matches
			type matchKey struct {
				signatureID string
				matchedCall string
			}
			actualMatches := map[matchKey]bool{}
			for _, m := range allMatches {
				actualMatches[matchKey{m.SignatureID, m.MatchedCall}] = true
			}

			// Verify each expected match
			for _, expected := range tc.expectedMatches {
				key := matchKey{expected.signatureID, expected.matchedCall}
				assert.True(t, actualMatches[key],
					"Expected match not found: signature=%s call=%s",
					expected.signatureID, expected.matchedCall)
			}

			// Verify all matches are app-level (no import dirs configured)
			appMatches, err := reader.GetApplicationSignatureMatches(context.Background())
			require.NoError(t, err)
			assert.Equal(t, len(allMatches), len(appMatches),
				"All matches should be app-level when no import directories are configured")

			// Verify match data fields
			for _, m := range allMatches {
				assert.NotEmpty(t, m.SignatureID)
				assert.NotEmpty(t, m.FilePath)
				assert.NotEmpty(t, m.Language)
				assert.Equal(t, tc.expectedMatches[0].language, m.Language)
			}
		})
	}
}

func TestScannerSkipSignatureMatching(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	fixtureAbs, err := filepath.Abs("testdata/test_go_capabilities")
	require.NoError(t, err)

	sigs, err := xbomsig.LoadSignatures("lang/golang", "", "")
	require.NoError(t, err)

	entStorage, err := storage.NewEntSqliteStorage(storage.EntSqliteClientConfig{
		Path: dbPath,
	})
	require.NoError(t, err)

	allLangCodes := getAllLanguageCodes()
	langs, err := languagesFromCodes(allLangCodes)
	require.NoError(t, err)

	scanner, err := NewScanner(ScannerConfig{
		AppDirectories:            []string{fixtureAbs},
		Languages:                 langs,
		SkipDependencyUsagePlugin: true,
		SkipSignatureMatching:     true,
		SignaturesToMatch:         sigs,
		Callbacks: &ScannerCallbackRegistry{
			OnScanStart: func() error { return nil },
			OnScanEnd:   func() error { return nil },
		},
	}, entStorage)
	require.NoError(t, err)

	err = scanner.Scan(context.Background())
	require.NoError(t, err)

	client, err := entStorage.Client()
	require.NoError(t, err)

	reader, err := NewReaderRepository(client)
	require.NoError(t, err)

	allMatches, err := reader.GetAllSignatureMatches(context.Background())
	require.NoError(t, err)
	assert.Empty(t, allMatches, "No matches expected when signature matching is skipped")
}
