package reporter

import (
	"os"

	controltowerv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
)

// bitbucketResolver resolves the sync environment from the standard Bitbucket
// Pipelines variables documented at
// https://support.atlassian.com/bitbucket-cloud/docs/variables-and-secrets/.
// Bitbucket Pipelines sets them on every build, and SafeDep's scan sandbox
// sets the same names for a sandboxed Bitbucket scan (safedep/vet#781).
type bitbucketResolver struct{}

func BitbucketSyncReporterResolver() SyncReporterEnvResolver {
	return &bitbucketResolver{}
}

var _ SyncReporterEnvResolver = &bitbucketResolver{}

func (b *bitbucketResolver) GetProjectSource() controltowerv1pb.Project_Source {
	return controltowerv1pb.Project_SOURCE_BITBUCKET
}

func (b *bitbucketResolver) GetProjectURL() string {
	fullName := os.Getenv("BITBUCKET_REPO_FULL_NAME")
	if fullName == "" {
		return ""
	}

	// Bitbucket Cloud has one host, and the documented variables carry no
	// origin URL.
	return "https://bitbucket.org/" + fullName
}

func (b *bitbucketResolver) GitRef() string {
	if branch := os.Getenv("BITBUCKET_BRANCH"); branch != "" {
		return branch
	}

	return os.Getenv("BITBUCKET_TAG")
}

func (b *bitbucketResolver) GitSha() string {
	return os.Getenv("BITBUCKET_COMMIT")
}

func (b *bitbucketResolver) Trigger() controltowerv1.ToolTrigger {
	if os.Getenv("BITBUCKET_PR_ID") != "" {
		return controltowerv1.ToolTrigger_TOOL_TRIGGER_PULL_REQUEST
	}
	if os.Getenv("BITBUCKET_TAG") != "" {
		return controltowerv1.ToolTrigger_TOOL_TRIGGER_TAG
	}

	// Pipelines has no variable that names the trigger event.
	return controltowerv1.ToolTrigger_TOOL_TRIGGER_MANUAL
}
