package acceptance

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

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

// Condition answers the script conditions of the harness: unix, git,
// docker and live.
func Condition(cond string) (bool, error) {
	switch cond {
	case "unix":
		return runtime.GOOS != "windows", nil
	case "git":
		_, err := exec.LookPath("git")
		return err == nil, nil
	case "docker":
		// A docker binary with no daemon cannot load an image.
		return exec.Command("docker", "info").Run() == nil, nil
	case "live":
		return os.Getenv(LiveEnv) == "1", nil
	}
	return false, errUnknownCondition(cond)
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
