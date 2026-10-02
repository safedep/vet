// Package errors prints the error of a command on stderr and exits. In
// rich and plain mode it passes through dry/tui/errors. In agent mode it
// prints one line with code=, message= and help= fields, which dry/tui
// does not have yet.
package errors

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/safedep/dry/tui/errors"
	"github.com/safedep/dry/tui/output"
	"github.com/safedep/dry/usefulerror"

	"github.com/safedep/vet/v2/internal/tui/escape"
)

// CodeUnknown is the code of an error that is not a usefulerror.
const CodeUnknown = "unknown"

var exit = os.Exit

// ExitWithCode prints the error on stderr and exits with the code.
func ExitWithCode(err error, code int) {
	if output.CurrentMode() != output.Agent {
		errors.ErrorExitWithCode(err, code)
		return
	}
	defer exit(code)
	if err == nil {
		return
	}
	// stderr is the last place to report an error. A failed write there
	// has no place left to go, and vet still exits with the code.
	if werr := WriteAgent(output.Stderr(), err); werr != nil {
		return
	}
}

// WriteAgent writes the agent line of an error:
//
//	ERR: code=usage_target message="..." help="..."
func WriteAgent(w io.Writer, err error) error {
	code, msg, help := CodeUnknown, err.Error(), ""
	if ue, ok := usefulerror.AsUsefulError(err); ok {
		code, msg, help = ue.Code(), ue.HumanError(), ue.Help()
	}
	_, werr := fmt.Fprintf(w, "ERR: code=%s message=%s help=%s\n",
		escape.Line(code), strconv.Quote(escape.Line(msg)), strconv.Quote(escape.Line(help)))
	return werr
}
