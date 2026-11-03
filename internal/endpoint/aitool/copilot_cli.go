package aitool

import "regexp"

var copilotCLIVersionRe = regexp.MustCompile(`GitHub Copilot CLI\s+v?(\d+\.\d+\.\d+)`)

type copilotCLIVerifier struct{}

func (d *copilotCLIVerifier) BinaryNames() []string { return []string{"copilot"} }
func (d *copilotCLIVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *copilotCLIVerifier) DisplayName() string   { return copilotAppDisplay }
func (d *copilotCLIVerifier) App() string           { return copilotApp }

func (d *copilotCLIVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	// Output format: "GitHub Copilot CLI 1.0.92.\nRun 'copilot update' ..."
	if m := copilotCLIVersionRe.FindStringSubmatch(stdout + stderr); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewCopilotCLIDiscoverer creates a discoverer for the standalone GitHub Copilot CLI binary.
func NewCopilotCLIDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &copilotCLIVerifier{}, config: config}, nil
}
