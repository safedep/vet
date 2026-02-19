package aitool

import (
	"regexp"
	"strings"
)

type amazonQVerifier struct{}

func (d *amazonQVerifier) BinaryNames() []string { return []string{"q", "amazon-q"} }
func (d *amazonQVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *amazonQVerifier) DisplayName() string   { return "Amazon Q" }
func (d *amazonQVerifier) App() string           { return "amazon_q" }

func (d *amazonQVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	combined := stdout + stderr
	if !strings.Contains(strings.ToLower(combined), "amazon") &&
		!strings.Contains(strings.ToLower(combined), "aws") {
		return "", false
	}
	re := regexp.MustCompile(`(\d+\.\d+\.\d+)`)
	if m := re.FindStringSubmatch(combined); len(m) > 1 {
		return m[1], true
	}
	return "", true
}

// NewAmazonQDiscoverer creates a discoverer for the Amazon Q CLI binary.
func NewAmazonQDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &amazonQVerifier{}, config: config}, nil
}
