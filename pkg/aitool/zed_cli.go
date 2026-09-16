package aitool

import "regexp"

// Zed is a high-performance code editor with built-in AI capabilities
// (https://zed.dev). It supports MCP via its context_servers config.
// Binary: zed
// Version: zed --version → "Zed 0.x.x" or "0.x.x (YYYYMMDD)"

var zedVersionRe = regexp.MustCompile(`(?i)zed\s+v?(\d+\.\d+\.\d+)`)

type zedVerifier struct{}

func (d *zedVerifier) BinaryNames() []string { return []string{"zed"} }
func (d *zedVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *zedVerifier) DisplayName() string   { return zedAppDisplay }
func (d *zedVerifier) App() string           { return zedApp }

func (d *zedVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	combined := stdout + stderr
	if m := zedVersionRe.FindStringSubmatch(combined); len(m) > 1 {
		return m[1], true
	}
	if m := semverLineRe.FindStringSubmatch(combined); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewZedCLIDiscoverer creates a discoverer for the Zed CLI binary.
func NewZedCLIDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &zedVerifier{}, config: config}, nil
}
