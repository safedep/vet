package command

import (
	"fmt"

	tuierrors "github.com/safedep/dry/tui/errors"
	"github.com/safedep/dry/usefulerror"
	"github.com/spf13/cobra"
)

// PresentableError converts a UsefulError into a human-readable error message.
// Non-UsefulErrors are returned unchanged.
func PresentableError(err error) error {
	if err == nil {
		return nil
	}
	if ue, ok := usefulerror.AsUsefulError(err); ok {
		return fmt.Errorf("%s: %s", ue.HumanError(), ue.Help())
	}
	return err
}

// RunCmd wraps a command execute function, converts UsefulErrors to
// human-readable messages, and exits with a styled error via tuierrors.
func RunCmd(fn func() error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if err := PresentableError(fn()); err != nil {
			tuierrors.ErrorExit(err)
		}
		return nil
	}
}
