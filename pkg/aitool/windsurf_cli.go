package aitool

import (
	"regexp"
	"strings"
)

type windsurfCLIVerifier struct{}

func (d *windsurfCLIVerifier) BinaryNames() []string { return []string{"windsurf"} }
func (d *windsurfCLIVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *windsurfCLIVerifier) DisplayName() string   { return "Windsurf" }
func (d *windsurfCLIVerifier) Host() string          { return windsurfHost }

func (d *windsurfCLIVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	// Output format: "1.107.0\n<commit-hash>\n<arch>"
	// Version is on the first line.
	combined := stdout + stderr
	firstLine := strings.SplitN(combined, "\n", 2)[0]
	re := regexp.MustCompile(`^(\d+\.\d+\.\d+)$`)
	if m := re.FindStringSubmatch(strings.TrimSpace(firstLine)); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewWindsurfCLIDiscoverer creates a discoverer for the Windsurf CLI binary.
func NewWindsurfCLIDiscoverer(_ DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &windsurfCLIVerifier{}}, nil
}
