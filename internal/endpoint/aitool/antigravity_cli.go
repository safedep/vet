package aitool

import "strings"

type antigravityCLIVerifier struct{}

func (d *antigravityCLIVerifier) BinaryNames() []string { return []string{"antigravity", "ag-kit"} }
func (d *antigravityCLIVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *antigravityCLIVerifier) DisplayName() string   { return "Antigravity" }
func (d *antigravityCLIVerifier) App() string           { return antigravityApp }

func (d *antigravityCLIVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	// Output format: "1.107.0\n<commit-hash>\n<arch>"
	// Version is on the first line.
	combined := stdout + stderr
	firstLine := strings.SplitN(combined, "\n", 2)[0]
	if m := semverLineRe.FindStringSubmatch(strings.TrimSpace(firstLine)); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewAntigravityCLIDiscoverer creates a discoverer for the Antigravity CLI binary.
func NewAntigravityCLIDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &antigravityCLIVerifier{}, config: config}, nil
}
