package githubci

import (
	"fmt"
	"io"
	"strings"

	"github.com/safedep/vet/v2/internal/ci"
)

// Annotate writes each annotation as an error workflow command. The runner
// reads the commands from the output of the step, and shows each one at
// its line in the diff of the pull request.
func Annotate(w io.Writer, as []ci.Annotation) error {
	for _, a := range as {
		props := "file=" + property(a.Path)
		if a.Line > 0 {
			props += fmt.Sprintf(",line=%d", a.Line)
		}
		if a.Title != "" {
			props += ",title=" + property(a.Title)
		}
		if _, err := fmt.Fprintf(w, "::error %s::%s\n", props, data(a.Text)); err != nil {
			return err
		}
	}
	return nil
}

// data escapes the message of a workflow command, so that text from the
// scanned code cannot end the command or start a new one.
var data = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace

// property escapes a property value of a workflow command.
var property = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace
