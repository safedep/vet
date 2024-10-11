package ci

import "net/url"

type gitRefType string

const (
	Branch      = gitRefType("branch")
	Tag         = gitRefType("tag")
	PullRequest = gitRefType("pull_request")
)

// Introspector defines a contract for implementing
// runtime information collector from various CI environments.
// This is modeled based on the default environments in GHA. But
// we will keep this minimal and add extended interfaces for
// additional CI specific information.
// https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/store-information-in-variables#default-environment-variables
type Introspector interface {
	// Returns the URL of the repository for which the CI job is running
	GetRepositoryURL() (url.URL, error)

	// Returns the repository name for which the CI job is running
	GetRepositoryName() (string, error)

	// Returns the event that triggered the CI job
	GetEvent() (gitRefType, error)

	// Returns the GitRef for which the CI job is running
	// This is fulled formed e.g. refs/heads/master
	GetGitRef() (string, error)

	// Get the ref name for which the CI job is running
	// This is the short form of the GitRef e.g. master
	GetRefName() (string, error)

	// Get the git ref type for which the CI job is running
	GetRefType() (string, error)

	// GitSHA returns the commit SHA for which the CI job is running
	GetGitSHA() (string, error)
}
