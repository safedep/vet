package reporter

import (
	"os"

	controltowerv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
)

type githubActionResolver struct{}

func GHASyncReporterReolver() SyncReporterEnvResolver {
	return &githubActionResolver{}
}

var _ SyncReporterEnvResolver = &githubActionResolver{}

func (g *githubActionResolver) GetProjectSource() controltowerv1pb.Project_Source {
	return controltowerv1pb.Project_SOURCE_GITHUB
}

func (g *githubActionResolver) GetProjectURL() string {
	return os.Getenv("GITHUB_SERVER_URL") + "/" + os.Getenv("GITHUB_REPOSITORY")
}

func (g *githubActionResolver) GitRef() string {
	return os.Getenv("GITHUB_REF")
}

func (g *githubActionResolver) GitSha() string {
	return os.Getenv("GITHUB_SHA")
}

func (g *githubActionResolver) Trigger() controltowerv1.ToolTrigger {
	switch eventName := os.Getenv("GITHUB_EVENT_NAME"); eventName {
	case "push":
		return controltowerv1.ToolTrigger_TOOL_TRIGGER_PUSH
	case "pull_request", "pull_request_target":
		return controltowerv1.ToolTrigger_TOOL_TRIGGER_PULL_REQUEST
	case "create":
		// In GitHub Actions, 'create' event with ref_type=tag indicates a tag was created
		if os.Getenv("GITHUB_REF_TYPE") == "tag" {
			return controltowerv1.ToolTrigger_TOOL_TRIGGER_TAG
		}
		return controltowerv1.ToolTrigger_TOOL_TRIGGER_UNSPECIFIED
	case "schedule":
		return controltowerv1.ToolTrigger_TOOL_TRIGGER_SCHEDULED
	case "workflow_dispatch", "repository_dispatch":
		return controltowerv1.ToolTrigger_TOOL_TRIGGER_MANUAL
	default:
		return controltowerv1.ToolTrigger_TOOL_TRIGGER_UNSPECIFIED
	}
}
