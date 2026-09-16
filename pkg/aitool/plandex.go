package aitool

import "regexp"

// Plandex is an open-source AI coding agent (https://github.com/plandex-ai/plandex).
// Binaries: plandex (and pdx as a short alias)
// Version: plandex version → "Plandex v2.x.x" or "plandex x.y.z"

var plandexVersionRe = regexp.MustCompile(`(?i)plandex\s+v?(\d+\.\d+\.\d+)`)

type plandexVerifier struct{}

func (d *plandexVerifier) BinaryNames() []string { return []string{"plandex", "pdx"} }
func (d *plandexVerifier) VerifyArgs() []string  { return []string{"version"} }
func (d *plandexVerifier) DisplayName() string   { return "Plandex" }
func (d *plandexVerifier) App() string           { return "plandex" }

func (d *plandexVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	combined := stdout + stderr
	if m := plandexVersionRe.FindStringSubmatch(combined); len(m) > 1 {
		return m[1], true
	}
	if m := semverLineRe.FindStringSubmatch(combined); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewPlandexDiscoverer creates a discoverer for the Plandex CLI binary.
func NewPlandexDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &plandexVerifier{}, config: config}, nil
}
