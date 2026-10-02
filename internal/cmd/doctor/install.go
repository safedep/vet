package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/plugins/cloud/inventory"
	"github.com/safedep/vet/v2/internal/plugins/cloud/tenantpolicy"
	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/codeusage"
	"github.com/safedep/vet/v2/internal/plugins/sinks"
	"github.com/safedep/vet/v2/plugin"
)

// installChecks check the binary and the plugins (the install checks).
func installChecks(cfg *config.Config) []Check {
	return []Check{pathCheck(os.Executable, exec.LookPath), pluginCheck(cfg)}
}

// pathCheck warns when the vet that PATH finds first is not this vet.
func pathCheck(self func() (string, error), look func(string) (string, error)) Check {
	exe, err := self()
	if err != nil {
		return Check{ID: "install.path", Status: Warn, Message: "vet could not find its own binary: " + err.Error()}
	}
	exe = realPath(exe)
	first, err := look("vet")
	if err != nil {
		return Check{ID: "install.path", Status: Warn, Message: exe + " is not on PATH", Fix: "Add the directory of vet to PATH."}
	}
	if first = realPath(first); first != exe {
		return Check{ID: "install.path", Status: Warn, Message: fmt.Sprintf("PATH finds %s first, not this vet (%s)", first, exe), Fix: "Remove the other vet, or put this one first on PATH."}
	}
	return Check{ID: "install.path", Status: Pass, Message: exe + " is the vet on PATH"}
}

func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	if a, err := filepath.Abs(p); err == nil {
		p = a
	}
	return p
}

// pluginCheck checks each plugins section of the config: the plugin must
// be a built-in one, and its options must be valid.
func pluginCheck(cfg *config.Config) Check {
	known := map[string]func(plugin.Config) error{
		codeusage.Name:    func(plugin.Config) error { return nil },
		tenantpolicy.Name: func(c plugin.Config) error { _, err := tenantpolicy.New(c); return err },
		inventory.Name:    func(c plugin.Config) error { _, err := inventory.New(c, nil); return err },
	}
	for _, s := range controls.Builtin() {
		known[s.Name] = func(c plugin.Config) error { _, err := s.New(c); return err }
	}
	for _, s := range sinks.Builtin() {
		known[s.Name] = func(c plugin.Config) error { _, err := s.New(c); return err }
	}
	names := make([]string, 0, len(cfg.Plugins))
	for n := range cfg.Plugins {
		names = append(names, n)
	}
	sort.Strings(names)
	var problems []string
	status := Pass
	for _, n := range names {
		build, ok := known[n]
		if !ok {
			problems = append(problems, fmt.Sprintf("vet has no plugin named %s", n))
			status = Warn
			continue
		}
		if err := build(plugin.MapConfig(cfg.PluginOptions(n))); err != nil {
			problems = append(problems, fmt.Sprintf("plugins.%s.options: %v", n, err))
			status = Fail
		}
	}
	if cfg.PluginEnabled(codeusage.Name, false) && !codeusage.Available() {
		problems = append(problems, "codeusage is on, and this vet build has no code analysis because it has no CGO")
		if status == Pass {
			status = Warn
		}
	}
	if len(problems) == 0 {
		return Check{ID: "plugins", Status: Pass, Message: fmt.Sprintf("%d built-in control plugins, every plugin section is valid", len(controls.Builtin()))}
	}
	return Check{ID: "plugins", Status: status, Message: strings.Join(problems, "; "), Fix: "vet config validate, and vet config schema get for the plugin options"}
}
