package githubactions_test

import (
	"io/fs"
	"time"
)

type fakeInfo struct{}

func (fakeInfo) Name() string       { return "f" }
func (fakeInfo) Size() int64        { return 10 }
func (fakeInfo) Mode() fs.FileMode  { return 0o644 }
func (fakeInfo) ModTime() time.Time { return time.Time{} }
func (fakeInfo) IsDir() bool        { return false }
func (fakeInfo) Sys() any           { return nil }
