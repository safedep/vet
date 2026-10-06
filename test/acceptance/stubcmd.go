package acceptance

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rogpeppe/go-internal/testscript"
	"google.golang.org/grpc/codes"

	"github.com/safedep/vet/v2/test/acceptance/stub"
)

type stubKey struct{}

// StartStub starts the stub SafeDep server for one script and points vet
// at it with the VET_* variables.
func StartStub(env *testscript.Env, fixtures string) error {
	s, err := stub.Start(fixtures)
	if err != nil {
		return err
	}
	env.Defer(func() {
		if err := s.Close(); err != nil {
			env.T().Log("stop the stub server:", err)
		}
	})
	env.Values[stubKey{}] = s
	env.Setenv("VET_CLOUD_ENDPOINTS_API", s.URL())
	env.Setenv("VET_CLOUD_ENDPOINTS_COMMUNITY", s.URL())
	env.Setenv("VET_GITHUB_API_URL", s.URL())
	env.Setenv("STUB_URL", s.URL())
	return nil
}

// cmdStub controls the stub server of the script:
//
//	stub delay <duration>
//	stub fail <service> <grpc code>
//	stub calls <service> <n>
//	stub readonly
//	stub comments
//	stub stop
func cmdStub(ts *testscript.TestScript, neg bool, args []string) {
	s, ok := ts.Value(stubKey{}).(*stub.Server)
	if !ok {
		ts.Fatalf("stub: the script has no stub server")
	}
	if len(args) == 0 {
		ts.Fatalf("usage: stub delay|fail|calls|stop ...")
	}
	if neg && args[0] != "calls" {
		ts.Fatalf("unsupported: ! stub %s", args[0])
	}
	switch {
	case args[0] == "delay" && len(args) == 2:
		d, err := time.ParseDuration(args[1])
		ts.Check(err)
		s.SetDelay(d)
	case args[0] == "fail" && len(args) == 3:
		code, ok := grpcCode(args[2])
		if !ok {
			ts.Fatalf("stub: unknown gRPC code %q", args[2])
		}
		s.Fail(args[1], code)
	case args[0] == "calls" && len(args) == 3:
		want, err := strconv.Atoi(args[2])
		ts.Check(err)
		got := s.Calls(args[1])
		if (got == want) == neg {
			ts.Fatalf("stub: %s has %d calls, want %s%d", args[1], got, map[bool]string{true: "not ", false: ""}[neg], want)
		}
	case args[0] == "readonly" && len(args) == 1:
		s.SetReadOnly(true)
	case args[0] == "comments" && len(args) == 1:
		for _, c := range s.Comments() {
			_, err := fmt.Fprintf(ts.Stdout(), "--- comment %d by %s on %s\n%s\n", c.ID, c.Login, c.Issue, c.Body)
			ts.Check(err)
		}
	case args[0] == "stop" && len(args) == 1:
		ts.Check(s.Close())
	default:
		ts.Fatalf("usage: stub delay <duration> | fail <service> <code> | calls <service> <n> | readonly | comments | stop")
	}
}

// grpcCode returns the gRPC code with a name, such as Unavailable.
func grpcCode(name string) (codes.Code, bool) {
	for c := codes.OK; c <= codes.Unauthenticated; c++ {
		if strings.EqualFold(c.String(), name) {
			return c, true
		}
	}
	return 0, false
}
