package aitool

import "strings"

type qwenCodeCLIVerifier struct{}

func (d *qwenCodeCLIVerifier) BinaryNames() []string { return []string{"qwen"} }
func (d *qwenCodeCLIVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *qwenCodeCLIVerifier) DisplayName() string   { return qwenCodeAppDisplay }
func (d *qwenCodeCLIVerifier) App() string           { return qwenCodeApp }

func (d *qwenCodeCLIVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	// Output format: "0.25.0"
	combined := stdout + stderr
	firstLine := strings.SplitN(combined, "\n", 2)[0]
	if m := semverLineRe.FindStringSubmatch(strings.TrimSpace(firstLine)); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewQwenCodeCLIDiscoverer creates a discoverer for the Qwen Code CLI binary.
func NewQwenCodeCLIDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &qwenCodeCLIVerifier{}, config: config}, nil
}
