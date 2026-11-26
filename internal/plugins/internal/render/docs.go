package render

import (
	"fmt"
	"net/url"

	"github.com/safedep/vet/v2/internal/github"
)

// RepoURL is the repository of vet.
const RepoURL = "https://github.com/safedep/vet"

// devRef is the branch of the docs of a development build.
const devRef = "v2"

// DocsRef is the git ref of the vet docs for a vet version: the tag of a
// release build, else the v2 branch.
func DocsRef(version string) string {
	if tag, ok := github.ReleaseTag(version); ok {
		return tag
	}
	return devRef
}

// ControlURL links the docs of a control for a vet version.
func ControlURL(version, control string) string {
	return fmt.Sprintf("%s/blob/%s/docs/controls.md#%s", RepoURL, DocsRef(version), url.PathEscape(control))
}
