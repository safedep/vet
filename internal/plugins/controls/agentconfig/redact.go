package agentconfig

import "regexp"

var (
	// envBlock is the env or headers object of an MCP server on one line.
	envBlock = regexp.MustCompile(`"(env|headers)"\s*:\s*\{[^{}]*\}`)
	// stringValue is one "key": "value" pair.
	stringValue = regexp.MustCompile(`("[^"]*"\s*:\s*)"(?:[^"\\]|\\.)*"`)
	// secretKey is a pair whose key names a secret.
	secretKey = regexp.MustCompile(`(?i)("[^"]*(token|secret|passw|pwd|apikey|api_key|auth|credential|cookie|session)[^"]*"\s*:\s*)"(?:[^"\\]|\\.)*"`)
	// userinfo is the user and the password of a URL.
	userinfo = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@:"']+:[^\s/@"']+@`)
)

// redact masks the secret values of a snippet: the values of an env or
// headers object, the values of keys that name a secret, and the password
// of a URL. A report must not carry a secret that a config file holds.
func redact(s string) string {
	s = envBlock.ReplaceAllStringFunc(s, func(block string) string {
		return stringValue.ReplaceAllString(block, `$1"***"`)
	})
	s = secretKey.ReplaceAllString(s, `$1"***"`)
	return userinfo.ReplaceAllString(s, `$1***@`)
}
