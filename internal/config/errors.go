package config

import (
	"errors"
	"fmt"

	"github.com/safedep/dry/usefulerror"
)

// Error codes of this package. Each one is a usage or configuration error,
// so the command exits with code 2.
const (
	CodeInvalid        = "config_invalid"
	CodeUnknownKey     = "config_unknown_key"
	CodeLocked         = "config_locked"
	CodeFileMissing    = "config_file_missing"
	CodeFileInvalid    = "config_file_invalid"
	CodeFileUnreadable = "config_file_unreadable"
)

func newError(code, msg, help string) error {
	return usefulerror.NewUsefulError().WithCode(code).WithHumanError(msg).WithHelp(help).WithMsg(msg)
}

// The errors of a value with the wrong type. Each text completes the
// sentence "KEY ...", as in "scan.concurrency must be a whole number".
var (
	errNotBool = errors.New("must be true or false")
	errNotInt  = errors.New("must be a whole number")
)

func invalidValue(key, raw string, origin Origin, want error) error {
	return newError(CodeInvalid, badValue(key, want.Error(), raw, origin.String()),
		fmt.Sprintf("Set %s to a valid value.", key))
}

// badValue says what a key must be, the value it got and where the value
// comes from, as `scan.concurrency must be a whole number, got "x" (flag)`.
func badValue(key, want, raw, from string) string {
	return fmt.Sprintf("%s %s, got %q (%s)", key, want, raw, from)
}

func unknownKey(key string) error {
	help := "Run vet config show to list the keys."
	if s := suggestKey(key); s != "" {
		help = fmt.Sprintf("Did you mean %s?", s)
	}
	return newError(CodeUnknownKey, fmt.Sprintf("%s: unknown key", key), help)
}

func lockedKey(key, file string) error {
	return newError(CodeLocked,
		fmt.Sprintf("%s is locked by the managed file %s", key, file),
		"Ask your administrator to change the managed file, or remove the flag.")
}
