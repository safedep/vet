package aitool

import "strings"

type cursorCLIVerifier struct{}

func (d *cursorCLIVerifier) BinaryNames() []string { return []string{"cursor"} }
func (d *cursorCLIVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *cursorCLIVerifier) DisplayName() string   { return "Cursor" }
func (d *cursorCLIVerifier) App() string           { return cursorApp }

func (d *cursorCLIVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	// Output format: "2.4.37\n<commit-hash>\n<arch>"
	// Version is on the first line.
	combined := stdout + stderr
	firstLine := strings.SplitN(combined, "\n", 2)[0]
	if m := semverLineRe.FindStringSubmatch(strings.TrimSpace(firstLine)); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewCursorCLIDiscoverer creates a discoverer for the Cursor CLI binary.
func NewCursorCLIDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &cursorCLIVerifier{}, config: config}, nil
}
