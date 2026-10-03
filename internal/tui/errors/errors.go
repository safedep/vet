// Package errors prints the error of a command on stderr and exits. In
// plain mode it passes through dry/tui/errors. In rich mode it prints the
// message in red with the code after it, and in agent mode one line with
// code=, message= and help= fields. dry/tui does not have these two yet.
package errors

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/safedep/dry/tui/errors"
	"github.com/safedep/dry/tui/output"
	"github.com/safedep/dry/usefulerror"

	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/section"
	"github.com/safedep/vet/v2/internal/tui/style"
)

// CodeUnknown is the code of an error that is not a usefulerror.
const CodeUnknown = "unknown"

// noHelp is the help text of a usefulerror with no help. vet does not
// print it.
const noHelp = "No additional help is available for this error."

var exit = os.Exit

// ExitWithCode prints the error on stderr and exits with the code.
func ExitWithCode(err error, code int) {
	mode := output.CurrentMode()
	if mode == output.Plain {
		errors.ErrorExitWithCode(err, code)
		return
	}
	defer exit(code)
	if err == nil {
		return
	}
	write := WriteRich
	if mode == output.Agent {
		write = WriteAgent
	}
	// stderr is the last place to report an error. A failed write there
	// has no place left to go, and vet still exits with the code.
	if werr := write(output.Stderr(), err); werr != nil {
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

// WriteRich writes an error for a person:
//
//	✗ unknown flag: --bogus  [usage_invalid]
//	› Run "vet scan --help" to list the arguments and the flags.
//
// The first line of the message is red, and the muted code follows it.
// The next lines of the message are normal text. With -v, vet also
// writes the additional help and the cause.
func WriteRich(w io.Writer, err error) error {
	ue, useful := usefulerror.AsUsefulError(err)
	msg := err.Error()
	if useful {
		msg = ue.HumanError()
	}
	first, rest, _ := strings.Cut(strings.TrimSpace(msg), "\n")
	head := style.Error(strings.TrimRight(first, " \t"))
	if useful {
		head += "  " + style.Faint("["+ue.Code()+"]")
	}
	lines := []string{head}
	for l := range strings.SplitSeq(rest, "\n") {
		if l = strings.TrimRight(l, " \t"); strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	if useful {
		lines = append(lines, details(ue)...)
	} else if output.CurrentVerbosity() >= output.Verbose {
		for c := unwrap(err); c != nil; c = unwrap(c) {
			lines = append(lines, causedBy(c.Error()))
		}
	}
	for _, l := range lines {
		if _, werr := fmt.Fprintln(w, l); werr != nil {
			return werr
		}
	}
	return nil
}

// details returns the hint lines of a usefulerror, and with -v its
// additional help and its cause.
func details(ue usefulerror.UsefulError) []string {
	var out []string
	hint := func(text string) {
		if text != "" && text != noHelp {
			out = append(out, section.Hint(text))
		}
	}
	hint(ue.Help())
	if u := ue.ReferenceURL(); u != "" {
		hint("Learn more: " + u)
	}
	if output.CurrentVerbosity() < output.Verbose {
		return out
	}
	hint(ue.AdditionalHelp())
	// A usefulerror with no wrapped error returns "code: message" as its
	// Error. That is no cause, so vet does not print it.
	if cause := ue.Error(); !strings.HasSuffix(cause, ue.HumanError()) {
		out = append(out, causedBy(cause))
	}
	return out
}

func causedBy(cause string) string { return style.Faint("  caused by: " + cause) }

func unwrap(err error) error {
	u, ok := err.(interface{ Unwrap() error })
	if !ok {
		return nil
	}
	return u.Unwrap()
}
