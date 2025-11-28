package parser

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/stretchr/testify/assert"
)

func Test_BunLockParser(t *testing.T) {
	manifest, err := parseBunLockFile("./fixtures/bun.lock", &ParserConfig{})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, len(manifest.Packages), 89)
	assert.Equal(t, manifest.Packages[0].Ecosystem, lockfile.NpmEcosystem)
}
