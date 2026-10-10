package agentconfig

import "regexp"

// quoted is a shell value: in double quotes as a JSON string escapes them,
// in double or single quotes, or bare.
const quoted = `\\"(?:[^"\\]|\\[^"])*\\"|"[^"]*"|'[^']*'|[^\s"'\\&;|]+`

var (
	// envBlock is the env or headers object of an MCP server on one line.
	envBlock = regexp.MustCompile(`"(env|headers)"\s*:\s*\{[^{}]*\}`)
	// stringValue is one "key": "value" pair.
	stringValue = regexp.MustCompile(`("[^"]*"\s*:\s*)"(?:[^"\\]|\\.)*"`)
	// secretKey is a pair whose key names a secret.
	secretKey = regexp.MustCompile(`(?i)("[^"]*(token|secret|passw|pwd|apikey|api_key|auth|credential|cookie|session)[^"]*"\s*:\s*)"(?:[^"\\]|\\.)*"`)
	// userinfo is the user and the password of a URL.
	userinfo = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@:"']+:[^\s/@"']+@`)
	// authHeader is the credential of an authorization header, as in a
	// curl -H "Authorization: Bearer <token>" command. A credential of any
	// length is a secret.
	authHeader = regexp.MustCompile(`(?i)(authorization\s*:\s*(?:(?:bearer|basic|token|digest)\s+)?)[^\s"']+`)
	// bearer is a bearer token outside a header, as in --auth "Bearer <token>".
	bearer = regexp.MustCompile(`(?i)\b(bearer\s+)[^\s"']+`)
	// secretFlag is the value of a command flag that names a secret, as in
	// --token=<token> or --api-key <key>, with any shell white space.
	secretFlag = regexp.MustCompile(`(?i)(--?[a-z0-9-]*(token|secret|passw|api-?key|auth)[a-z0-9-]*(?:=|\s+))(` + quoted + `)`)
	// secretQuery is the value of a URL query key that names a secret.
	secretQuery = regexp.MustCompile(`(?i)([?&][a-z0-9_-]*(token|secret|passw|apikey|api_key|key|sig|auth)[a-z0-9_-]*=)[^&\s"']+`)
	// secretEnv is the value of a shell variable that names a secret, as in
	// API_TOKEN=<token> npm run deploy. The name starts a shell word or a
	// JSON string, so a URL query key is not a variable.
	secretEnv = regexp.MustCompile(`(?i)(^|[\s;&|("'])([a-z0-9_]*(token|secret|password|passwd|api_key|apikey)[a-z0-9_]*=)(` + quoted + `)`)
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
	s = authHeader.ReplaceAllString(s, `$1***`)
	s = bearer.ReplaceAllString(s, `$1***`)
	s = secretFlag.ReplaceAllString(s, `$1***`)
	s = secretQuery.ReplaceAllString(s, `$1***`)
	s = secretEnv.ReplaceAllString(s, `$1$2***`)
	return userinfo.ReplaceAllString(s, `$1***@`)
}
