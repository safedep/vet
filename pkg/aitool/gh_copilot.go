package aitool

import (
	"regexp"
	"strings"
)

type ghCopilotVerifier struct{}

func (d *ghCopilotVerifier) BinaryNames() []string { return []string{"gh"} }
func (d *ghCopilotVerifier) VerifyArgs() []string  { return []string{"extension", "list"} }
func (d *ghCopilotVerifier) DisplayName() string   { return "GitHub Copilot CLI" }
func (d *ghCopilotVerifier) App() string           { return "gh_copilot" }

func (d *ghCopilotVerifier) VerifyOutput(stdout, _ string) (string, bool) {
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "github/gh-copilot") {
			re := regexp.MustCompile(`v?(\d+\.\d+\.\d+)`)
			if m := re.FindStringSubmatch(line); len(m) > 1 {
				return m[1], true
			}
			return "", true
		}
	}
	return "", false
}

// NewGhCopilotDiscoverer creates a discoverer for the GitHub Copilot gh extension.
func NewGhCopilotDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &ghCopilotVerifier{}, config: config}, nil
}
