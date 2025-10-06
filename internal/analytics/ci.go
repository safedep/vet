package analytics

import "os"

type environmentType string

const (
	environmentTypeGitHubActions environmentType = "github_actions"
	environmentTypeGitLabCI      environmentType = "gitlab_ci"
	environmentTypeDocker        environmentType = "docker"
)

// Map of environment variables which if set will determine environments
var ciEnvVars = map[string]environmentType{
	"GITHUB_ACTION":    environmentTypeGitHubActions,
	"GITHUB_WORKFLOW":  environmentTypeGitHubActions,
	"GITLAB_CI":        environmentTypeGitLabCI,
	"CI_COMMIT_BRANCH": environmentTypeGitLabCI,
}

func TrackCI() {
	uniqueTypes := make(map[environmentType]bool)
	for envVar, envVarType := range ciEnvVars {
		if os.Getenv(envVar) != "" {
			uniqueTypes[envVarType] = true
		}
	}

	for envVarType := range uniqueTypes {
		trackCiEvent(envVarType)
	}
}

func trackCiEvent(envVarType environmentType) {
	switch envVarType {
	case environmentTypeGitHubActions:
		TrackEvent(eventScanEnvGitHubActions)
	case environmentTypeGitLabCI:
		TrackEvent(eventScanEnvGitLabCI)
	case environmentTypeDocker:
		TrackEvent(eventScanEnvDocker)
	}
}
