package aitool

import "regexp"

type claudeCLIVerifier struct{}

func (d *claudeCLIVerifier) BinaryNames() []string { return []string{"claude"} }
func (d *claudeCLIVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *claudeCLIVerifier) DisplayName() string   { return "Claude Code" }
func (d *claudeCLIVerifier) Host() string          { return claudeCodeHost }

func (d *claudeCLIVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	combined := stdout + stderr
	re := regexp.MustCompile(`(?i)claude[^\d]*v?(\d+\.\d+\.\d+)`)
	if m := re.FindStringSubmatch(combined); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewClaudeCLIDiscoverer creates a discoverer for the Claude Code CLI binary.
func NewClaudeCLIDiscoverer(_ DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &claudeCLIVerifier{}}, nil
}
