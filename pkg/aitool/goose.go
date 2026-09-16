package aitool

import "regexp"

// Goose is an open-source AI agent by Block (https://github.com/block/goose).
// Binary: goose
// Version: goose --version → "goose x.y.z" or "Goose CLI x.y.z"

var gooseVersionRe = regexp.MustCompile(`(?i)goose(?:\s+cli)?\s+v?(\d+\.\d+\.\d+)`)

type gooseVerifier struct{}

func (d *gooseVerifier) BinaryNames() []string { return []string{"goose"} }
func (d *gooseVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *gooseVerifier) DisplayName() string   { return "Goose" }
func (d *gooseVerifier) App() string           { return "goose" }

func (d *gooseVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	combined := stdout + stderr
	if m := gooseVersionRe.FindStringSubmatch(combined); len(m) > 1 {
		return m[1], true
	}
	if m := semverLineRe.FindStringSubmatch(combined); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewGooseDiscoverer creates a discoverer for the Goose CLI binary.
func NewGooseDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &gooseVerifier{}, config: config}, nil
}
