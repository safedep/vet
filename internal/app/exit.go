package app

import (
	"context"
	"errors"
	"strings"

	"github.com/safedep/dry/usefulerror"
)

// Exit codes of the terminal experience design, section 10.
const (
	ExitOK          = 0
	ExitGateFailed  = 1
	ExitUsage       = 2
	ExitRuntime     = 3
	ExitInterrupted = 130
)

// ErrGateFailed means that the gate that the user set failed. It is a report
// outcome and not an error, so vet prints no error for it.
var ErrGateFailed = errors.New("the gate failed")

// ErrInterrupted means that a signal stopped the command after vet saved
// the progress.
var ErrInterrupted = errors.New("a signal stopped vet")

// CodeUsage is the usefulerror code of a bad flag, argument or target.
const CodeUsage = "usage_invalid"

// usagePrefixes are the usefulerror code prefixes of usage and
// configuration errors. Each one exits with code 2.
var usagePrefixes = []string{"usage_", "config_", "state_dir_", "credentials_", "policy_invalid"}

// UsageError returns a usage error with a message and a help text.
func UsageError(msg, help string) error {
	return usefulerror.NewUsefulError().WithCode(CodeUsage).WithHumanError(msg).WithHelp(help).WithMsg(msg)
}

// ExitCode maps an error of a command to its exit code.
func ExitCode(err error) int {
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, ErrGateFailed):
		return ExitGateFailed
	case errors.Is(err, ErrInterrupted), errors.Is(err, context.Canceled):
		return ExitInterrupted
	}
	if ue, ok := usefulerror.AsUsefulError(err); ok {
		for _, p := range usagePrefixes {
			if strings.HasPrefix(ue.Code(), p) {
				return ExitUsage
			}
		}
	}
	return ExitRuntime
}
