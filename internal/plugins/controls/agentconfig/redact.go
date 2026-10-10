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
	// authScheme is the credential of an HTTP authorization value, as in a
	// curl -H "Authorization: Bearer <token>" command.
	authScheme = regexp.MustCompile(`(?i)\b(bearer|basic|token)\s+[a-z0-9._~+/=-]{8,}`)
	// secretFlag is the value of a command flag that names a secret, as in
	// --token=<token> or --api-key <key>.
	secretFlag = regexp.MustCompile(`(?i)(--?[a-z0-9-]*(token|secret|passw|api-?key)[a-z0-9-]*[= ])("[^"]*"|'[^']*'|[^\s"']+)`)
	// secretQuery is the value of a URL query key that names a secret.
	secretQuery = regexp.MustCompile(`(?i)([?&][a-z0-9_-]*(token|secret|passw|apikey|api_key|key|sig|auth)[a-z0-9_-]*=)[^&\s"']+`)
	// secretEnv is the value of a shell variable that names a secret, as in
	// API_TOKEN=<token> npm run deploy.
	secretEnv = regexp.MustCompile(`\b([A-Z0-9_]*(TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY)[A-Z0-9_]*=)[^\s"']+`)
)

// redact masks the secret values of a text from a config file: the values
// of an env or headers object, the values of keys, flags, query keys and
// shell variables that name a secret, an authorization credential and the
// password of a URL. A report must not carry a secret that a config file
// holds, in a snippet or in a title.
func redact(s string) string {
	s = envBlock.ReplaceAllStringFunc(s, func(block string) string {
		return stringValue.ReplaceAllString(block, `$1"***"`)
	})
	s = secretKey.ReplaceAllString(s, `$1"***"`)
	s = authScheme.ReplaceAllString(s, `$1 ***`)
	s = secretFlag.ReplaceAllString(s, `$1***`)
	s = secretQuery.ReplaceAllString(s, `$1***`)
	s = secretEnv.ReplaceAllString(s, `$1***`)
	return userinfo.ReplaceAllString(s, `$1***@`)
}
