package aitool

import "regexp"

type aiderVerifier struct{}

func (d *aiderVerifier) BinaryNames() []string { return []string{"aider"} }
func (d *aiderVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *aiderVerifier) DisplayName() string   { return "Aider" }
func (d *aiderVerifier) Host() string          { return "aider" }

func (d *aiderVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	re := regexp.MustCompile(`aider\s+v?(\d+\.\d+\.\d+)`)
	if m := re.FindStringSubmatch(stdout); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewAiderDiscoverer creates a discoverer for the Aider CLI binary.
func NewAiderDiscoverer(_ DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &aiderVerifier{}}, nil
}
