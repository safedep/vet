package engine

import (
	"errors"
	"fmt"
	"io/fs"
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

func TestPseudoMounts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only Linux mounts pseudo file systems in the tree")
	}
	mounts := pseudoMounts()
	assert.True(t, mounts["/proc"])
	proc := plugin.Artifact{Kind: plugin.ArtifactDirectory, Path: "/proc/self"}
	assert.True(t, systemDirs(proc)("."), "a target on a pseudo file system is not walked")
	assert.False(t, systemDirs(plugin.Artifact{Kind: plugin.ArtifactDirectory, Path: t.TempDir()})("."))
}

func TestReadErrorCollapsesPermissionErrors(t *testing.T) {
	a := &fs.PathError{Op: "open", Path: "/root/a/package-lock.json", Err: fs.ErrPermission}
	b := fmt.Errorf("go/binary: /usr/sbin/x: %w", &fs.PathError{Op: "open", Path: "/usr/sbin/x", Err: fs.ErrPermission})
	assert.Equal(t, permissionDenied, readError(a))
	assert.Equal(t, readError(a), readError(b))
	assert.Equal(t, "boom", readError(errors.New("boom")))
}
