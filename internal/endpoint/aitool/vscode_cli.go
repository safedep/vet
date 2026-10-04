package aitool

import "strings"

type vscodeCLIVerifier struct{}

func (d *vscodeCLIVerifier) BinaryNames() []string { return []string{"code"} }
func (d *vscodeCLIVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *vscodeCLIVerifier) DisplayName() string   { return "VS Code" }
func (d *vscodeCLIVerifier) App() string           { return vscodeApp }

func (d *vscodeCLIVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	// Output format: "1.110.1\n<commit-hash>\n<arch>"
	// Version is on the first line.
	combined := stdout + stderr
	firstLine := strings.SplitN(combined, "\n", 2)[0]
	if m := semverLineRe.FindStringSubmatch(strings.TrimSpace(firstLine)); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewVSCodeCLIDiscoverer creates a discoverer for the VS Code CLI binary.
func NewVSCodeCLIDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &vscodeCLIVerifier{}, config: config}, nil
}
