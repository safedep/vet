// Package lockfile is the lockfile poisoning control. It reads each npm
// lockfile and reports an entry that resolves from an untrusted registry,
// or from a URL that does not match the package name. It ports the v1
// lfp analyzer.
package lockfile

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/packagelockjson"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the plugin name and the config key under plugins.
const Name = "lockfile"

// Control ids.
const (
	IDUntrustedRegistry = "untrusted-registry"
	IDPathMismatch      = "registry-path-mismatch"
)

const (
	npmRegistry = "https://registry.npmjs.org"
	cweURL      = "https://cwe.mitre.org/data/definitions/349.html"
)

// npmInconsistentURLs lists the packages that the npm registry serves from
// the path of another package name.
var npmInconsistentURLs = map[string]string{
	"strip-ansi-cjs":   "https://registry.npmjs.org/strip-ansi/-/",
	"wrap-ansi-cjs":    "https://registry.npmjs.org/wrap-ansi/-/",
	"string-width-cjs": "https://registry.npmjs.org/string-width/-/",
}

// Options are plugins.lockfile.options.
type Options struct {
	// TrustedRegistries are registry URLs that vet trusts in addition to
	// the public npm registry.
	TrustedRegistries []string `json:"trusted_registries"`
}

// Control reports poisoned lockfile entries.
type Control struct {
	user    []*url.URL
	trusted []*url.URL
}

// New builds the control from its options.
func New(cfg plugin.Config) (plugin.Control, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	c := &Control{}
	for _, raw := range append([]string{npmRegistry}, o.TrustedRegistries...) {
		u, err := parseURL(raw)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("lockfile: trusted registry %q is not a URL", raw)
		}
		c.trusted = append(c.trusted, u)
	}
	c.user = c.trusted[1:]
	return c, nil
}

// Controls describes the control ids.
func (c *Control) Controls() []plugin.ControlInfo {
	return []plugin.ControlInfo{
		{
			ID: IDUntrustedRegistry, Family: finding.FamilyLockfile, Severity: finding.SeverityHigh,
			Title:       "Lockfile entry from an untrusted registry",
			Description: "A lockfile entry resolves from a host that is not a trusted registry. An attacker can edit a lockfile to install code from a host they control.",
		},
		{
			ID: IDPathMismatch, Family: finding.FamilyLockfile, Severity: finding.SeverityHigh,
			Title:       "Lockfile entry with a URL of another package",
			Description: "The resolved URL of a lockfile entry does not match the package name. An attacker can edit a lockfile to install another package under a trusted name.",
		},
	}
}

type entry struct {
	Resolved     string           `json:"resolved"`
	Link         bool             `json:"link"`
	Dependencies map[string]entry `json:"dependencies"`
}

type npmLockfile struct {
	LockfileVersion int              `json:"lockfileVersion"`
	Packages        map[string]entry `json:"packages"`
	Dependencies    map[string]entry `json:"dependencies"`
}

// Evaluate reads the npm lockfile of the manifest from the target.
func (c *Control) Evaluate(_ context.Context, m *model.Manifest, _ plugin.State) ([]finding.Finding, error) {
	if m.Extractor != packagelockjson.Name || m.Root == nil {
		return nil, nil
	}
	data, err := fs.ReadFile(m.Root, m.Path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", m.Path, err)
	}
	var lf npmLockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("decode %s: %w", m.Path, err)
	}

	entries := map[string]entry{}
	for path, e := range lf.Packages {
		if name := nameOf(path); name != "" {
			entries[path] = e
		}
	}
	if len(lf.Packages) == 0 {
		flatten("", lf.Dependencies, entries)
	}

	paths := make([]string, 0, len(entries))
	for p := range entries {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var out []finding.Finding
	for _, path := range paths {
		e := entries[path]
		if e.Resolved == "" || e.Link {
			continue
		}
		name := nameOf(path)
		locus := finding.Locus{Path: m.Path, StartLine: lineOf(data, path, e.Resolved), Snippet: e.Resolved}
		locus.EndLine = locus.StartLine
		key := finding.Key{Discriminator: path}
		if !c.trustedSource(e.Resolved) {
			out = append(out, c.finding(IDUntrustedRegistry, locus, key,
				fmt.Sprintf("%s resolves from an untrusted host", name),
				fmt.Sprintf("The lockfile installs %s from %s. The host is not a trusted registry.", name, e.Resolved)))
		}
		if !c.followsConvention(e.Resolved, name) {
			out = append(out, c.finding(IDPathMismatch, locus, key,
				fmt.Sprintf("%s resolves from the URL of another package", name),
				fmt.Sprintf("The lockfile installs %s from %s. The URL path does not match the package name.", name, e.Resolved)))
		}
	}
	return out, nil
}

func (c *Control) finding(id string, locus finding.Locus, key finding.Key, title, desc string) finding.Finding {
	f := finding.ForFile(finding.Meta{
		ControlID: id, Family: finding.FamilyLockfile, Severity: finding.SeverityHigh,
		Confidence: finding.ConfidenceMedium, Title: title, Description: desc,
	}, locus, key)
	f.Evidence = []finding.Evidence{{Source: "lockfile", Summary: locus.Snippet}}
	f.References = []string{cweURL}
	f.Remediation = &finding.Remediation{
		Summary: "Make sure that the lockfile change is intended. Regenerate the lockfile from a trusted registry, or add the registry to plugins.lockfile.options.trusted_registries.",
	}
	return f
}

// flatten turns the nested dependencies of a lockfile version 1 into the
// node_modules paths of version 2.
func flatten(prefix string, deps map[string]entry, out map[string]entry) {
	for name, e := range deps {
		path := prefix + "node_modules/" + name
		out[path] = e
		flatten(path+"/", e.Dependencies, out)
	}
}

// nameOf returns the package name of a node_modules path, or "" for a path
// with no node_modules, such as the root or a workspace.
func nameOf(path string) string {
	i := strings.LastIndex(path, "node_modules/")
	if i < 0 {
		return ""
	}
	return path[i+len("node_modules/"):]
}

// lineOf returns the line of the resolved URL of an entry.
func lineOf(data []byte, path, resolved string) int {
	start := bytes.Index(data, []byte(`"`+path+`"`))
	if start < 0 {
		start = 0
	}
	i := bytes.Index(data[start:], []byte(`"`+resolved+`"`))
	if i < 0 {
		return 0
	}
	return bytes.Count(data[:start+i], []byte("\n")) + 1
}

// parseURL parses a URL. It accepts git+ssh://host:owner/repo, which
// url.Parse rejects.
func parseURL(raw string) (*url.URL, error) {
	const gitSSH = "git+ssh://"
	if len(raw) > len(gitSSH) && strings.EqualFold(raw[:len(gitSSH)], gitSSH) {
		if i := strings.Index(raw[len(gitSSH):], ":"); i >= 0 {
			j := len(gitSSH) + i
			raw = raw[:j] + "/" + raw[j+1:]
		}
	}
	return url.Parse(raw)
}

func (c *Control) trustedSource(resolved string) bool {
	u, err := parseURL(resolved)
	if err != nil {
		return false
	}
	if u.Scheme == "file" || u.Scheme == "" {
		return true
	}
	for _, t := range c.trusted {
		if t.Scheme != "" && t.Scheme != u.Scheme {
			continue
		}
		if !strings.EqualFold(t.Hostname(), u.Hostname()) {
			continue
		}
		if t.Port() != "" && t.Port() != u.Port() {
			continue
		}
		if t.Path != "" && !strings.HasPrefix(u.Path, t.Path) {
			continue
		}
		return true
	}
	return false
}

// followsConvention reports whether the URL path starts with the package
// name, as the npm registry serves it: <registry>/<name>/-/<file>.
func (c *Control) followsConvention(resolved, name string) bool {
	if known, ok := npmInconsistentURLs[name]; ok && strings.HasPrefix(resolved, known) {
		return true
	}
	u, err := parseURL(resolved)
	if err != nil {
		return false
	}
	if u.Scheme == "file" || u.Scheme == "" {
		return true
	}
	if u.Path == "" {
		return false
	}
	path := strings.TrimPrefix(u.Path, "/")
	accept := []string{name}
	for _, t := range c.trusted {
		if base := strings.Trim(t.Path, "/"); base != "" {
			accept = append(accept, base+"/"+name)
		}
	}
	if slices.Contains(accept, strings.Split(path, "/-/")[0]) {
		return true
	}
	for _, t := range c.user {
		if strings.HasPrefix(resolved, t.String()) {
			return true
		}
	}
	return false
}

var (
	_ plugin.Control   = (*Control)(nil)
	_ plugin.Describer = (*Control)(nil)
)
