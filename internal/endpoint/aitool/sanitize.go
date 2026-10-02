package aitool

import (
	"strings"
)

// argSecretPatterns defines key=value prefixes that may contain secrets.
var argSecretPatterns = []string{
	"--token=",
	"--api-key=",
	"--password=",
	"--secret=",
	"--credentials=",
}

// SanitizeArgs redacts argument values that match secret patterns.
// For example, "--token=sk-ant-..." becomes "--token=<REDACTED>".
func SanitizeArgs(args []string) []string {
	if args == nil {
		return nil
	}
	result := make([]string, len(args))
	for i, arg := range args {
		result[i] = sanitizeArg(arg)
	}
	return result
}

func sanitizeArg(arg string) string {
	lower := strings.ToLower(arg)
	for _, pattern := range argSecretPatterns {
		if strings.HasPrefix(lower, pattern) {
			return arg[:len(pattern)] + "<REDACTED>"
		}
	}
	return arg
}
