package aitool

import "strings"

type geminiCLIVerifier struct{}

func (d *geminiCLIVerifier) BinaryNames() []string { return []string{"gemini"} }
func (d *geminiCLIVerifier) VerifyArgs() []string  { return []string{"--version"} }
func (d *geminiCLIVerifier) DisplayName() string   { return geminiAppDisplay }
func (d *geminiCLIVerifier) App() string           { return geminiApp }

func (d *geminiCLIVerifier) VerifyOutput(stdout, stderr string) (string, bool) {
	// Output format: "0.62.0"
	combined := stdout + stderr
	firstLine := strings.SplitN(combined, "\n", 2)[0]
	if m := semverLineRe.FindStringSubmatch(strings.TrimSpace(firstLine)); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// NewGeminiCLIDiscoverer creates a discoverer for the Gemini CLI CLI binary.
func NewGeminiCLIDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &cliToolDiscoverer{verifier: &geminiCLIVerifier{}, config: config}, nil
}
