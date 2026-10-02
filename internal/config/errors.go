package config

import (
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

func invalidValue(key, raw string, origin Origin, cause error) error {
	from := string(origin.Layer)
	if origin.Source != "" {
		from += " " + origin.Source
	}
	return newError(CodeInvalid,
		fmt.Sprintf("%s: invalid value %q from %s: %v", key, raw, from, cause),
		fmt.Sprintf("Set a valid value for %s.", key))
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
