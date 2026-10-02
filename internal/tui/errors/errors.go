// Package errors passes through dry/tui/errors.
package errors

import "github.com/safedep/dry/tui/errors"

// ExitWithCode prints the error on stderr and exits with the code. It
// renders a usefulerror with its code and help.
func ExitWithCode(err error, code int) { errors.ErrorExitWithCode(err, code) }
