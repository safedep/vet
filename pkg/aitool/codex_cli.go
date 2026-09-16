package aitool

import "regexp"

// OpenAI Codex CLI (https://github.com/openai/codex)
// Binary: codex
// Version: codex --version → "codex x.y.z" or bare semver

var codexVersionRe = regexp.MustCompile(`(?i)codex\s+v?(\d+\.\d+\.\d+)`)

type codexVerifier struct{}

func (d *codexVerifier) BinaryNames() []string { return []string{"codex"} }
func (d *codexVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *codexVerifier) DisplayName() string   { return "OpenAI Codex" }
func (d *codexVerifier) App() string           { return "openai_codex" }

func (d *codexVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	combined := stdout + stderr
	if m := codexVersionRe.FindStringSubmatch(combined); len(m) > 1 {
		return m[1], true
	}
	if m := semverLineRe.FindStringSubmatch(combined); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewCodexCLIDiscoverer creates a discoverer for the OpenAI Codex CLI binary.
func NewCodexCLIDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &codexVerifier{}, config: config}, nil
}
