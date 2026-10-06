package aitool

import "regexp"

var augmentCLIVersionRe = regexp.MustCompile(`^(\d+\.\d+\.\d+)\s+\(commit [0-9a-f]+\)`)

type augmentCLIVerifier struct{}

func (d *augmentCLIVerifier) BinaryNames() []string { return []string{"auggie"} }
func (d *augmentCLIVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *augmentCLIVerifier) DisplayName() string   { return augmentAppDisplay }
func (d *augmentCLIVerifier) App() string           { return augmentApp }

func (d *augmentCLIVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	// Output format: "0.36.0 (commit 7c61e5bb)"
	if m := augmentCLIVersionRe.FindStringSubmatch(stdout + stderr); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewAugmentCLIDiscoverer creates a discoverer for Augment Code's Auggie CLI binary.
func NewAugmentCLIDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &augmentCLIVerifier{}, config: config}, nil
}
