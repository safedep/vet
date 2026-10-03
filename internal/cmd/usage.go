package cmd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
)

// The argument errors of the cobra validators. TestCobraUsageErrors fails
// when a cobra update changes one of them.
var (
	argsExact   = regexp.MustCompile(`^accepts (\d+) arg\(s\), received (\d+)$`)
	argsAtMost  = regexp.MustCompile(`^accepts at most (\d+) arg\(s\), received (\d+)$`)
	argsAtLeast = regexp.MustCompile(`^requires at least (\d+) arg\(s\), only received (\d+)$`)
	argsRange   = regexp.MustCompile(`^accepts between (\d+) and (\d+) arg\(s\), received (\d+)$`)
	unknownCmd  = regexp.MustCompile(`^unknown command "(.*)" for "(.*)"`)
)

// usageError turns an error of cobra into a usage error. c is the command
// that failed. The message names the command and its arguments in place of
// the text of cobra, and the help names the help of that command.
func usageError(c *cobra.Command, err error) error {
	path := c.CommandPath()
	msg, hint := strings.TrimSpace(err.Error()), helpHint(c)
	first, rest, _ := strings.Cut(msg, "\n")
	names := argNames(c.Use)

	if m := unknownCmd.FindStringSubmatch(first); m != nil {
		if isLeaf(c) {
			msg = fmt.Sprintf("%s takes no argument, got %q", path, m[1])
		} else {
			msg = first
			if s := suggestions(c, rest); s != "" {
				hint = fmt.Sprintf("Did you mean %s? %s", s, hint)
			}
		}
	} else if m := argsExact.FindStringSubmatch(msg); m != nil {
		msg = fmt.Sprintf("%s takes %s (%s), got %s", path, arguments(m[1]), names, m[2])
		if m[2] == "0" {
			msg = fmt.Sprintf("%s needs %s: %s", path, arguments(m[1]), names)
		}
	} else if m := argsAtMost.FindStringSubmatch(msg); m != nil {
		msg = fmt.Sprintf("%s takes at most %s (%s), got %s", path, arguments(m[1]), names, m[2])
	} else if m := argsAtLeast.FindStringSubmatch(msg); m != nil {
		msg = fmt.Sprintf("%s needs at least %s: %s", path, arguments(m[1]), names)
	} else if m := argsRange.FindStringSubmatch(msg); m != nil {
		msg = fmt.Sprintf("%s takes %s to %s (%s), got %s", path, m[1], arguments(m[2]), names, m[3])
	}
	return app.UsageError(msg, hint)
}

func helpHint(c *cobra.Command) string {
	if isLeaf(c) {
		return fmt.Sprintf("Run %q to see the arguments and the flags.", c.CommandPath()+" --help")
	}
	return fmt.Sprintf("Run %q to list the commands and the flags.", c.CommandPath()+" --help")
}

func isLeaf(c *cobra.Command) bool { return c.Runnable() && !c.HasAvailableSubCommands() }

// suggestions reads the "Did you mean this?" block of cobra, one command
// name on each line, and returns the full command paths.
func suggestions(c *cobra.Command, block string) string {
	var out []string
	for l := range strings.SplitSeq(block, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasSuffix(l, "?") {
			continue
		}
		out = append(out, c.CommandPath()+" "+l)
	}
	return strings.Join(out, " or ")
}

// argNames returns the argument names of a Use line, as "KEY VALUE" for
// "set KEY VALUE" and "TARGET" for "scan [TARGET]".
func argNames(use string) string {
	_, args, _ := strings.Cut(use, " ")
	return strings.NewReplacer("[", "", "]", "").Replace(args)
}

func arguments(n string) string {
	if n == "1" {
		return "1 argument"
	}
	return n + " arguments"
}
