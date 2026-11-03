package aitool

import (
	"net/url"
	"strings"
)

// argSecretPatterns defines key=value prefixes that may contain secrets.
// vet matches them with "_" read as "-", so --api_key matches --api-key.
var argSecretPatterns = []string{
	"--token=",
	"--api-key=",
	"--apikey=",
	"--access-token=",
	"--auth-token=",
	"--password=",
	"--secret=",
	"--credentials=",
}

// flagForm returns arg in lower case with "_" read as "-". The length does
// not change, so a prefix of the result is a prefix of arg.
func flagForm(arg string) string { return strings.ReplaceAll(strings.ToLower(arg), "_", "-") }

const redacted = "<REDACTED>"

// SanitizeArgs redacts argument values that match secret patterns:
// "--token=sk-ant-..." becomes "--token=<REDACTED>", the value after a
// bare "--token" becomes "<REDACTED>", and a URL loses its credentials.
func SanitizeArgs(args []string) []string {
	if args == nil {
		return nil
	}
	result := make([]string, len(args))
	for i, arg := range args {
		if i > 0 && isSecretFlag(args[i-1]) {
			result[i] = redacted
			continue
		}
		result[i] = sanitizeArg(arg)
	}
	return result
}

func sanitizeArg(arg string) string {
	lower := flagForm(arg)
	for _, pattern := range argSecretPatterns {
		if strings.HasPrefix(lower, pattern) {
			return arg[:len(pattern)] + redacted
		}
	}
	return SanitizeURL(arg)
}

// isSecretFlag reports whether arg is a secret flag with its value in the
// next argument, as in "--token sk-ant-...".
func isSecretFlag(arg string) bool {
	lower := flagForm(arg)
	for _, pattern := range argSecretPatterns {
		if lower == strings.TrimSuffix(pattern, "=") {
			return true
		}
	}
	return false
}

// secretQueryKeys are the parts of a query parameter name that mark its
// value as a secret.
var secretQueryKeys = []string{"token", "key", "secret", "password", "auth", "credential"}

// SanitizeURL removes the user and the password of a URL, and redacts the
// query values whose names look like secrets. A string that is not an
// absolute URL stays as it is.
func SanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	changed := false
	if u.User != nil {
		u.User = url.User("REDACTED")
		changed = true
	}
	q := u.Query()
	for k := range q {
		lower := strings.ToLower(k)
		for _, s := range secretQueryKeys {
			if strings.Contains(lower, s) {
				q.Set(k, "REDACTED")
				changed = true
				break
			}
		}
	}
	if !changed {
		return raw
	}
	u.RawQuery = q.Encode()
	return u.String()
}
