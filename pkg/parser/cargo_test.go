package parser

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_CargoLockParser(t *testing.T) {
	manifest, err := parseCargoLockFile("./fixtures/rust/Cargo.lock", &ParserConfig{})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, len(manifest.Packages), 43) // total 43 deps
}
