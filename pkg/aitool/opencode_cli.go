package aitool

import "strings"

type openCodeCLIVerifier struct{}

func (d *openCodeCLIVerifier) BinaryNames() []string { return []string{"opencode"} }
func (d *openCodeCLIVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *openCodeCLIVerifier) DisplayName() string   { return openCodeAppDisplay }
func (d *openCodeCLIVerifier) App() string           { return openCodeApp }

func (d *openCodeCLIVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	// Output format: "1.18.34"
	combined := stdout + stderr
	firstLine := strings.SplitN(combined, "\n", 2)[0]
	if m := semverLineRe.FindStringSubmatch(strings.TrimSpace(firstLine)); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewOpenCodeCLIDiscoverer creates a discoverer for the OpenCode CLI binary.
func NewOpenCodeCLIDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &openCodeCLIVerifier{}, config: config}, nil
}
