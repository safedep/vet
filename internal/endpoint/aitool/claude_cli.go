package aitool

import "regexp"

var (
	claudeCLIVersionRe  = regexp.MustCompile(`(?i)claude[^\d]*v?(\d+\.\d+\.\d+)`)
	claudeCLIVersionRe2 = regexp.MustCompile(`(\d+\.\d+\.\d+)\s*\(.*(?i)claude`)
)

type claudeCLIVerifier struct{}

func (d *claudeCLIVerifier) BinaryNames() []string { return []string{"claude"} }
func (d *claudeCLIVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *claudeCLIVerifier) DisplayName() string   { return "Claude Code" }
func (d *claudeCLIVerifier) App() string           { return claudeCodeApp }

func (d *claudeCLIVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	combined := stdout + stderr

	// Match "Claude Code v1.2.3" or "claude v1.2.3"
	if m := claudeCLIVersionRe.FindStringSubmatch(combined); len(m) > 1 {
		return m[1], true
	}

	// Match "1.2.3 (Claude Code)" format
	if m := claudeCLIVersionRe2.FindStringSubmatch(combined); len(m) > 1 {
		return m[1], true
	}

	return "", false
}

// NewClaudeCLIDiscoverer creates a discoverer for the Claude Code CLI binary.
func NewClaudeCLIDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &claudeCLIVerifier{}, config: config}, nil
}
