package acceptance

import (
	"debug/buildinfo"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/rogpeppe/go-internal/testscript"
)

// LiveEnv turns on the live scripts.
const LiveEnv = "ACCEPTANCE_LIVE"

// Sandbox gives each script its own home and the XDG directories under
// it, so that no script reads or writes the host config, state, cache or
// keychain (acceptance suite design, section 3.2). testscript does not
// forward the host environment, so SAFEDEP_*, CLAUDECODE, AI_AGENT and CI
// are unset unless a script sets them.
func Sandbox(env *testscript.Env) error {
	home := filepath.Join(env.WorkDir, "home")
	dirs := map[string]string{
		"HOME":            home,
		"USERPROFILE":     home,
		"XDG_CONFIG_HOME": filepath.Join(home, ".config"),
		"XDG_STATE_HOME":  filepath.Join(home, ".local", "state"),
		"XDG_CACHE_HOME":  filepath.Join(home, ".cache"),
		"XDG_DATA_HOME":   filepath.Join(home, ".local", "share"),
		"AppData":         filepath.Join(home, "AppData", "Roaming"),
		"LocalAppData":    filepath.Join(home, "AppData", "Local"),
	}
	for k, v := range dirs {
		if err := os.MkdirAll(v, 0o700); err != nil {
			return err
		}
		env.Setenv(k, v)
	}
	// No script touches the host keychain. vet keeps the credentials in a
	// plaintext file under the sandbox home.
	env.Setenv("VET_CLOUD_KEYCHAIN_FILE", filepath.Join(home, "keychain.json"))
	return nil
}

// vetBinary is the path of the vet binary under test.
var vetBinary string

// Condition answers the script conditions of the harness: unix, git,
// docker, root, live and cgo. cgo holds when the vet binary was built with
// CGO, which code analysis needs.
func Condition(cond string) (bool, error) {
	switch cond {
	case "cgo":
		return builtWithCGO(vetBinary)
	case "unix":
		return runtime.GOOS != "windows", nil
	case "git":
		_, err := exec.LookPath("git")
		return err == nil, nil
	case "docker":
		// A docker binary with no daemon cannot load an image.
		return exec.Command("docker", "info").Run() == nil, nil
	case "root":
		return runtime.GOOS != "windows" && os.Geteuid() == 0, nil
	case "live":
		return os.Getenv(LiveEnv) == "1", nil
	case "harness-version":
		return builtWithHarnessVersion(vetBinary)
	}
	return false, errUnknownCondition(cond)
}

func builtWithCGO(bin string) (bool, error) {
	if bin == "" {
		return false, nil
	}
	info, err := buildinfo.ReadFile(bin)
	if err != nil {
		return false, err
	}
	for _, s := range info.Settings {
		if s.Key == "CGO_ENABLED" {
			return s.Value == "1", nil
		}
	}
	return false, nil
}

type errUnknownCondition string

func (e errUnknownCondition) Error() string { return "unknown testscript condition " + string(e) }

// ForwardEnv copies host variables into the script environment.
func ForwardEnv(env *testscript.Env, keys ...string) {
	for _, key := range keys {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			env.Setenv(key, v)
		}
	}
}

// HarnessVersion is the version of the binary that the harness builds. It
// has the form of a release build, with no v, so a script can check the
// release logic. A VET_BIN binary has its own version.
const HarnessVersion = "2.0.0-alpha.20260101000000"

// HarnessCommit is the commit of the harness build. The stub GitHub API
// names it for the tag of HarnessVersion.
const HarnessCommit = "1111111111111111111111111111111111111111"

func builtWithHarnessVersion(bin string) (bool, error) {
	if bin == "" {
		return false, nil
	}
	info, err := buildinfo.ReadFile(bin)
	if err != nil {
		return false, err
	}
	for _, s := range info.Settings {
		if s.Key == "-ldflags" {
			return strings.Contains(s.Value, "version.version="+HarnessVersion), nil
		}
	}
	return false, nil
}
