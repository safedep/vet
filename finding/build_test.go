package finding

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShorten(t *testing.T) {
	assert.Equal(t, "abc", Shorten("abc", 5))
	assert.Equal(t, "ab...", Shorten("abcdef", 5))
	assert.Equal(t, "日本...", Shorten("日本語のテキスト", 5), "a cut never splits a character")
}
