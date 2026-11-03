package aitool

import "regexp"

// Amp versions are "0.0.<build>-g<commit>" followed by the release time.
var ampCLIVersionRe = regexp.MustCompile(`^(\d+\.\d+\.\d+)-g[0-9a-f]+\s+\(released`)

type ampCLIVerifier struct{}

func (d *ampCLIVerifier) BinaryNames() []string { return []string{"amp"} }
func (d *ampCLIVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *ampCLIVerifier) DisplayName() string   { return ampAppDisplay }
func (d *ampCLIVerifier) App() string           { return ampApp }

func (d *ampCLIVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	// Output format: "0.0.1791288059-gdc93b0 (released 2026-10-06T12:00:59.000Z, 1h ago)"
	if m := ampCLIVersionRe.FindStringSubmatch(stdout + stderr); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewAmpCLIDiscoverer creates a discoverer for the Amp CLI binary.
func NewAmpCLIDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &ampCLIVerifier{}, config: config}, nil
}
