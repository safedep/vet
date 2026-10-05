//go:build linux

package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnescapeMount(t *testing.T) {
	assert.Equal(t, "/mnt/my disk", unescapeMount(`/mnt/my\040disk`))
	assert.Equal(t, "/proc", unescapeMount("/proc"))
}
