package aitool

import "regexp"

var codexCLIVersionRe = regexp.MustCompile(`codex-cli\s+v?(\d+\.\d+\.\d+)`)

type codexCLIVerifier struct{}

func (d *codexCLIVerifier) BinaryNames() []string { return []string{"codex"} }
func (d *codexCLIVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *codexCLIVerifier) DisplayName() string   { return codexAppDisplay }
func (d *codexCLIVerifier) App() string           { return codexApp }

func (d *codexCLIVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	// Output format: "codex-cli 0.160.1", possibly preceded by warnings.
	if m := codexCLIVersionRe.FindStringSubmatch(stdout + stderr); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewCodexCLIDiscoverer creates a discoverer for the OpenAI Codex CLI binary.
func NewCodexCLIDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &codexCLIVerifier{}, config: config}, nil
}
