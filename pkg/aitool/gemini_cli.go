package aitool

import "regexp"

var geminiVersionRe = regexp.MustCompile(`(?i)gemini(?:\s+cli)?\s+v?(\d+\.\d+\.\d+)`)

type geminiVerifier struct{}

func (d *geminiVerifier) BinaryNames() []string { return []string{"gemini"} }
func (d *geminiVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *geminiVerifier) DisplayName() string   { return geminiAppDisplay }
func (d *geminiVerifier) App() string           { return geminiApp }

func (d *geminiVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	combined := stdout + stderr
	if m := geminiVersionRe.FindStringSubmatch(combined); len(m) > 1 {
		return m[1], true
	}
	// Fallback: bare semver on first line
	if m := semverLineRe.FindStringSubmatch(combined); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewGeminiCLIDiscoverer creates a discoverer for the Google Gemini CLI binary.
func NewGeminiCLIDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &geminiVerifier{}, config: config}, nil
}
