package engine

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/plugin"
)

func TestSystemDirs(t *testing.T) {
	root := plugin.Artifact{Kind: plugin.ArtifactDirectory, Path: "/"}
	assert.True(t, systemDirs(root)("dev"))
	assert.True(t, systemDirs(root)("System/Volumes"))
	assert.False(t, systemDirs(root)("usr"))

	project := plugin.Artifact{Kind: plugin.ArtifactDirectory, Path: t.TempDir()}
	assert.False(t, systemDirs(project)("dev"), "dev is a system directory under a file system root only")

	image := plugin.Artifact{Kind: plugin.ArtifactImage, Path: "/"}
	assert.False(t, systemDirs(image)("proc"))
}

func TestPseudoFS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only Linux mounts pseudo file systems in the tree")
	}
	assert.True(t, pseudoFS("/proc"))
	assert.False(t, pseudoFS(t.TempDir()))
}
