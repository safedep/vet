package acceptance

import (
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rogpeppe/go-internal/testscript"
)

// Commands are the script commands that the harness adds to the testscript
// builtins. They have the dry/acceptance shape (decisions D17).
func Commands() map[string]func(ts *testscript.TestScript, neg bool, args []string) {
	return map[string]func(ts *testscript.TestScript, neg bool, args []string){
		"execexit":    cmdExecExit,
		"expandenv":   cmdExpandEnv,
		"replace":     cmdReplace,
		"capture":     cmdCapture,
		"jsonq":       cmdJSONQ,
		"reportcheck": cmdReportCheck,
		"stub":        cmdStub,
		"sleep":       cmdSleep,
		"schemacheck": cmdSchemaCheck,
		"mode":        cmdMode,
		"imagetar":    cmdImageTar,
	}
}

// cmdMode asserts the permission bits of a file or a directory:
// mode <path> <octal>. Windows has no such bits, so a script that uses it
// runs on unix only.
func cmdMode(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 2 {
		ts.Fatalf("usage: mode <path> <octal>")
	}
	want, err := strconv.ParseUint(args[1], 8, 32)
	ts.Check(err)
	info, err := os.Stat(ts.MkAbs(args[0]))
	ts.Check(err)
	if got := info.Mode().Perm(); got != os.FileMode(want) {
		ts.Fatalf("%s has mode %#o, want %#o", args[0], got, want)
	}
}

// cmdSleep waits, for example for a background scan to reach a stage:
// sleep <duration>.
func cmdSleep(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 1 {
		ts.Fatalf("usage: sleep <duration>")
	}
	d, err := time.ParseDuration(args[0])
	ts.Check(err)
	time.Sleep(d)
}

// cmdExecExit runs a command and asserts its exact exit code:
// execexit <code> <cmd> [args...].
func cmdExecExit(ts *testscript.TestScript, neg bool, args []string) {
	if neg {
		ts.Fatalf("unsupported: ! execexit")
	}
	if len(args) < 2 {
		ts.Fatalf("usage: execexit <code> <cmd> [args...]")
	}
	want, err := strconv.Atoi(args[0])
	ts.Check(err)
	got := 0
	if err := ts.Exec(args[1], args[2:]...); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			ts.Fatalf("run %s: %v", args[1], err)
		}
		got = ee.ExitCode()
	}
	if got != want {
		ts.Fatalf("%s exited with code %d, want %d", strings.Join(args[1:], " "), got, want)
	}
}

// cmdExpandEnv replaces $VAR and ${VAR} in files with the script
// environment: expandenv <file>...
func cmdExpandEnv(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) == 0 {
		ts.Fatalf("usage: expandenv <file>...")
	}
	for _, f := range args {
		path := ts.MkAbs(f)
		data, err := os.ReadFile(path)
		ts.Check(err)
		ts.Check(os.WriteFile(path, []byte(os.Expand(string(data), ts.Getenv)), 0o600))
	}
}

// cmdReplace replaces every old with new in a file: replace <file> <old>
// <new>. The strings take Go escapes such as \n.
func cmdReplace(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 3 {
		ts.Fatalf("usage: replace <file> <old> <new>")
	}
	path := ts.MkAbs(args[0])
	data, err := os.ReadFile(path)
	ts.Check(err)
	oldS, newS := unescape(ts, args[1]), unescape(ts, args[2])
	if !strings.Contains(string(data), oldS) {
		ts.Fatalf("%s does not contain %q", args[0], oldS)
	}
	ts.Check(os.WriteFile(path, []byte(strings.ReplaceAll(string(data), oldS, newS)), 0o600))
}

// cmdCapture sets a variable to the first group of a regexp, or to the
// whole match: capture <var> <regexp> [file]. The file defaults to the
// stdout of the last command.
func cmdCapture(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) < 2 || len(args) > 3 {
		ts.Fatalf("usage: capture <var> <regexp> [file]")
	}
	file := "stdout"
	if len(args) == 3 {
		file = args[2]
	}
	re, err := regexp.Compile(args[1])
	ts.Check(err)
	m := re.FindStringSubmatch(ts.ReadFile(file))
	if m == nil {
		ts.Fatalf("no match for %q in %s", args[1], file)
	}
	v := m[0]
	if len(m) > 1 {
		v = m[1]
	}
	ts.Setenv(args[0], v)
}

func unescape(ts *testscript.TestScript, s string) string {
	u, err := strconv.Unquote(`"` + strings.ReplaceAll(s, `"`, `\"`) + `"`)
	ts.Check(err)
	return u
}
