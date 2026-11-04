package agentconfig

import (
	"regexp"
	"strings"
)

// secretWords are the words of a key that names a secret.
const secretWords = `(?:token|secret|passw|pwd|api[_-]?key|auth|credential|cookie|session)`

// quoted is a shell value: in double quotes as a JSON string escapes them,
// in double or single quotes, or bare.
const quoted = `\\"(?:[^"\\]|\\[^"])*\\"|"[^"]*"|'[^']*'|[^\s"'\\&;|]+`

var (
	// envBlock is the env or headers object of an MCP server on one line:
	// a JSON object, a TOML inline table or a YAML flow mapping.
	envBlock = regexp.MustCompile(`(?i)"?\b(env|envs|environment|headers|http_headers|env_http_headers)"?\s*[:=]\s*\{[^{}]*\}`)
	// blockValue is one pair of such an object, with a quoted or a bare key
	// and value.
	blockValue = regexp.MustCompile(`((?:"[^"]*"|'[^']*'|[^\s{},:="']+)\s*[:=]\s*)(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s,{}]+)`)
	// secretKey is a JSON pair whose key names a secret.
	secretKey = regexp.MustCompile(`(?i)("[^"]*` + secretWords + `[^"]*"\s*:\s*)"(?:[^"\\]|\\.)*"`)
	// secretTOML is a TOML pair with a bare key that names a secret.
	secretTOML = regexp.MustCompile(`(?i)(\b[\w.-]*` + secretWords + `[\w.-]*\s*=\s*)(?:"(?:[^"\\]|\\.)*"|'[^']*')`)
	// secretYAML is a YAML pair whose key names a secret: at the start of a
	// line, after a list dash, or in a flow mapping. A header in a shell
	// command, such as -H "Authorization: x", is not a key.
	secretYAML = regexp.MustCompile(`(?i)((?:^|[{,])\s*(?:-\s+)?[\w.-]*` + secretWords + `[\w.-]*:\s+)[^\s,}][^,}]*`)
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
		name, body, _ := strings.Cut(block, "{")
		return name + "{" + blockValue.ReplaceAllString(body, `$1"***"`)
	})
	s = secretKey.ReplaceAllString(s, `$1"***"`)
	s = secretTOML.ReplaceAllString(s, `$1"***"`)
	s = secretYAML.ReplaceAllString(s, `$1***`)
	s = authHeader.ReplaceAllString(s, `$1***`)
	s = bearer.ReplaceAllString(s, `$1***`)
	s = secretFlag.ReplaceAllString(s, `$1***`)
	s = secretQuery.ReplaceAllString(s, `$1***`)
	s = secretEnv.ReplaceAllString(s, `$1$2***`)
	return userinfo.ReplaceAllString(s, `$1***@`)
}
