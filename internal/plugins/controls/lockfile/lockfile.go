// Package lockfile is the lockfile poisoning control (control catalog,
// phase 2). It reports an entry that resolves from an untrusted registry or
// from a URL of another package, an entry whose integrity hash changes with
// no version change, a lockfile change with no change to the manifest file
// next to it, and an installed npm package that the lockfile does not list.
// It reads each npm lockfile itself, as the v1 lfp analyzer did, and the
// resolved URL of the other lockfiles.
package lockfile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	pathpkg "path"
	"slices"
	"sort"
	"strings"

	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/packagelockjson"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the plugin name and the config key under plugins.
const Name = "lockfile"

// Control ids.
const (
	IDUntrustedRegistry = "untrusted-registry"
	IDPathMismatch      = "registry-path-mismatch"
	IDIntegrityChanged  = "integrity-changed"
	IDLockfileOnly      = "lockfile-only-change"
)

const (
	npmRegistry = "https://registry.npmjs.org"
	// githubPackagesHost serves npm tarballs at
	// /download/<@scope/name>/<version>/<hash>, not at <name>/-/<file>.
	githubPackagesHost = "npm.pkg.github.com"
	cweURL             = "https://cwe.mitre.org/data/definitions/349.html"
)

// npmAliases maps the npm aliases that common packages install, such as
// the aliases of glob through @isaacs/cliui, to the package that a registry
// serves for them. The alias has the path of that package on any registry,
// public or private. directAliases reads the aliases of the project.
var npmAliases = map[string]string{
	"strip-ansi-cjs":   "strip-ansi",
	"wrap-ansi-cjs":    "wrap-ansi",
	"string-width-cjs": "string-width",
}

// Options are plugins.lockfile.options.
type Options struct {
	// TrustedRegistries are registry URLs that vet trusts in addition to
	// the public npm registry.
	TrustedRegistries []string `json:"trusted_registries"`
}

// defaultRegistries are the public registries of each ecosystem.
var defaultRegistries = map[model.Ecosystem][]string{
	model.EcosystemNpm:   {npmRegistry, "https://registry.yarnpkg.com"},
	model.EcosystemPyPI:  {"https://pypi.org", "https://files.pythonhosted.org"},
	model.EcosystemCargo: {"https://github.com/rust-lang/crates.io-index", "https://index.crates.io", "https://static.crates.io"},
}

// Control reports poisoned lockfile entries.
type Control struct {
	locks lockIndex
	user  []*url.URL
	// trusted holds the default registries of each ecosystem and the
	// user registries.
	trusted map[model.Ecosystem][]*url.URL
}

// New builds the control from its options.
func New(cfg plugin.Config) (plugin.Control, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	c := &Control{trusted: map[model.Ecosystem][]*url.URL{}}
	for _, raw := range o.TrustedRegistries {
		u, err := parseURL(raw)
		if err != nil || u.Host == "" || u.Scheme == "" {
			return nil, fmt.Errorf("lockfile: trusted registry %q is not a URL with a scheme and a host", raw)
		}
		u.Path = pathpkg.Clean("/" + u.Path)
		c.user = append(c.user, u)
	}
	for eco, raws := range defaultRegistries {
		for _, raw := range raws {
			u, err := parseURL(raw)
			if err != nil {
				return nil, err
			}
			c.trusted[eco] = append(c.trusted[eco], u)
		}
		c.trusted[eco] = append(c.trusted[eco], c.user...)
	}
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
			Description: "The resolved URL of a lockfile entry does not match the package name. An attacker can edit a lockfile to install another package under a trusted name. A trusted registry does not turn off this check.",
		},
		{
			ID: IDIntegrityChanged, Family: finding.FamilyLockfile, Severity: finding.SeverityHigh,
			Title:       "Lockfile integrity hash changed with no version change",
			Description: "The change keeps the version of a lockfile entry and changes its integrity hash. The lockfile now installs other code under the same name and version.",
		},
		{
			ID: IDLockfileOnly, Family: finding.FamilyLockfile, Severity: finding.SeverityHigh,
			Title:       "Lockfile change with no manifest change",
			Description: "The change edits a lockfile and leaves the manifest file next to it as it was. A tool such as npm update makes this change, and so does an attacker who edits the lockfile by hand.",
		},
		installedInfo,
	}
}

type entry struct {
	Version  string `json:"version"`
	Resolved string `json:"resolved"`
	Link     bool   `json:"link"`
}

// legacyEntry is an entry of the nested dependencies of lockfile version 1.
type legacyEntry struct {
	Version      string                 `json:"version"`
	Resolved     string                 `json:"resolved"`
	Dependencies map[string]legacyEntry `json:"dependencies"`
}

type npmLockfile struct {
	Packages     map[string]entry       `json:"packages"`
	Dependencies map[string]legacyEntry `json:"dependencies"`
}

// Evaluate checks the entries of a lockfile manifest, and the packages of
// an installed npm manifest against the lockfile of the project.
func (c *Control) Evaluate(ctx context.Context, m *model.Manifest, s plugin.State) ([]finding.Finding, error) {
	if m.Kind == model.ManifestKindInstalled {
		return c.installed(ctx, m, s)
	}
	if m.Kind != model.ManifestKindLockfile {
		return nil, nil
	}
	var out []finding.Finding
	switch {
	case m.Extractor == packagelockjson.Name && m.Root != nil:
		fs, err := c.npmLockfile(m)
		if err != nil {
			return nil, err
		}
		out = fs
	case m.Extractor != packagelockjson.Name:
		out = c.resolvedEntries(m)
	}
	out = append(out, c.integrity(m)...)
	if m.LockfileOnly {
		out = append(out, lockfileOnly(m))
	}
	return out, nil
}

// npmLockfile reads the npm lockfile of the manifest from the target.
func (c *Control) npmLockfile(m *model.Manifest) ([]finding.Finding, error) {
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

	aliases := directAliases(m.Root, pathpkg.Join(pathpkg.Dir(m.Path), "package.json"))

	var out []finding.Finding
	for _, path := range paths {
		e := entries[path]
		if e.Resolved == "" || e.Link {
			continue
		}
		name := nameOf(path)
		target := ""
		if path == "node_modules/"+name {
			target = aliases[name]
		}
		locus := finding.Locus{Path: m.Path, StartLine: lineOf(data, path, e.Resolved), Snippet: e.Resolved}
		locus.EndLine = locus.StartLine
		key := finding.Key{Discriminator: path}
		if !c.trustedSource(model.EcosystemNpm, e.Resolved) {
			out = append(out, c.finding(IDUntrustedRegistry, locus, key,
				fmt.Sprintf("%s resolves from an untrusted host", name),
				fmt.Sprintf("The lockfile installs %s from %s. The host is not a trusted registry.", name, e.Resolved)))
		}
		if !c.followsConvention(e.Resolved, name, target) {
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
		Summary: remediation(id),
	}
	return f
}

// remediation says how to fix a finding. A trusted registry does not turn
// off registry-path-mismatch, so its fix does not name trusted_registries.
func remediation(id string) string {
	if id == IDPathMismatch {
		return "Make sure that the lockfile change is intended. The resolved URL must name the package of the entry. Regenerate the lockfile."
	}
	return "Make sure that the lockfile change is intended. Regenerate the lockfile from a trusted registry. To trust the registry, add its full URL to plugins.lockfile.options.trusted_registries"
}

// directAliases returns the npm aliases that a package.json declares, as in
// "debug-v4": "npm:debug@4.3.4", from alias to package name. npm installs a
// direct alias at node_modules/<alias>. The lockfile also records the
// package name of an alias, but an attacker can edit the lockfile. So the
// check reads the alias from package.json, which a reviewer sees in the
// change. The aliases of workspace members and of dependencies are not read.
// A package.json that vet cannot read gives no aliases, so the check reports
// more entries, not fewer.
func directAliases(root fs.FS, path string) map[string]string {
	data, err := fs.ReadFile(root, path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		log.Warnf("lockfile: read %s: %v", path, err)
		return nil
	}
	var pj struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		log.Warnf("lockfile: decode %s: %v", path, err)
		return nil
	}
	out := map[string]string{}
	for _, deps := range []map[string]string{pj.Dependencies, pj.DevDependencies, pj.OptionalDependencies, pj.PeerDependencies} {
		for alias, spec := range deps {
			if target := aliasTarget(spec); target != "" {
				out[alias] = target
			}
		}
	}
	return out
}

// aliasTarget returns the package name of an npm alias spec, such as debug
// for npm:debug@^4 and @types/node for npm:@types/node, or "" for another
// spec.
func aliasTarget(spec string) string {
	target, ok := strings.CutPrefix(spec, "npm:")
	if !ok || target == "" {
		return ""
	}
	if i := strings.Index(target[1:], "@"); i >= 0 {
		target = target[:i+1]
	}
	return target
}

// flatten turns the nested dependencies of a lockfile version 1 into the
// node_modules paths of version 2.
func flatten(prefix string, deps map[string]legacyEntry, out map[string]entry) {
	for name, e := range deps {
		path := prefix + "node_modules/" + name
		out[path] = entry{Version: e.Version, Resolved: e.Resolved}
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

func (c *Control) trustedSource(eco model.Ecosystem, resolved string) bool {
	u, err := parseURL(resolved)
	if err != nil {
		return false
	}
	if local(u) {
		return true
	}
	path := cleanPath(u)
	for _, t := range c.trustedOf(eco) {
		if t.Scheme != "" && t.Scheme != u.Scheme {
			continue
		}
		if !strings.EqualFold(t.Hostname(), u.Hostname()) {
			continue
		}
		if t.Port() != "" && t.Port() != u.Port() {
			continue
		}
		if base := basePath(t); base != "" && path != base && !strings.HasPrefix(path, base+"/") {
			continue
		}
		return true
	}
	return false
}

// local reports whether a resolved URL is a file on the machine. That is a
// file URL, or a path with no scheme and no host. A protocol-relative URL
// such as //host/pkg.tgz has a host, so it is not local.
func local(u *url.URL) bool {
	return u.Scheme == "file" || (u.Scheme == "" && u.Host == "")
}

// cleanPath returns the URL path with no leading slash and no empty
// segments. unsafePath refuses the paths that it cannot read as npm does.
func cleanPath(u *url.URL) string {
	return strings.TrimPrefix(pathpkg.Clean("/"+u.Path), "/")
}

// basePath returns the path of a trusted registry with no slash at either
// end.
func basePath(t *url.URL) string {
	return strings.Trim(t.Path, "/")
}

// unsafePath reports whether npm would read the path of a URL as another
// path than Go does. Node removes the dot segments of the raw path, and it
// reads a backslash as a slash. Go decodes %2f to a slash before it splits
// the segments. So debug%2f-%2fd/../evil/-/evil.tgz is the path of debug for
// Go and the path of evil for npm. No package manager writes such a path,
// so the checks refuse it. The one encoded slash that npm writes is the slash
// of a scoped name, as in @types%2fnode.
func unsafePath(u *url.URL) bool {
	raw := strings.ToLower(u.EscapedPath())
	if strings.Contains(raw, `\`) || strings.Contains(raw, "%5c") {
		return true
	}
	for _, seg := range strings.Split(raw, "/") {
		switch strings.ReplaceAll(seg, "%2e", ".") {
		case ".", "..":
			return true
		}
		if strings.Contains(seg, "%2f") && !scopedName(seg) {
			return true
		}
	}
	return false
}

// scopedName reports whether an escaped path segment is one scoped npm
// name, as in @types%2fnode.
func scopedName(seg string) bool {
	scope, name, ok := strings.Cut(seg, "%2f")
	return ok && strings.HasPrefix(scope, "@") && len(scope) > 1 && name != "" && !strings.Contains(name, "%2f")
}

// followsConvention reports whether the URL path starts with the package
// name, as the npm registry serves it: <registry>/<name>/-/<file>. When the
// name is an alias, the path can start with the target package of the alias
// instead. target is "" for a name that is not a direct alias.
func (c *Control) followsConvention(resolved, name, target string) bool {
	u, err := parseURL(resolved)
	if err != nil {
		return false
	}
	if local(u) {
		return true
	}
	if u.Path == "" || unsafePath(u) {
		return false
	}
	path := cleanPath(u)
	// A user registry can serve the layout of GitHub Packages, as GitHub
	// Enterprise Server does. The public registries serve only the npm
	// layout.
	github := strings.EqualFold(u.Hostname(), githubPackagesHost) || c.userHost(u)
	names := []string{name}
	if real, ok := npmAliases[name]; ok {
		names = append(names, real)
	}
	if target != "" {
		names = append(names, target)
	}
	for _, rest := range c.registryPaths(u, path) {
		if slices.Contains(names, strings.Split(rest, "/-/")[0]) {
			return true
		}
		if github && slices.ContainsFunc(names, func(n string) bool { return githubPackagesPath(rest, n) }) {
			return true
		}
	}
	return false
}

// userHost reports whether a user trusted registry is on the host of the URL.
func (c *Control) userHost(u *url.URL) bool {
	for _, t := range c.user {
		if strings.EqualFold(t.Hostname(), u.Hostname()) {
			return true
		}
	}
	return false
}

// registryPaths returns the URL path as it is, and the path after the base
// path of each trusted registry on the host of the URL. A base path can hold
// /-/ itself, as /api/v4/groups/<id>/-/packages/npm does. So the check removes
// the base path before it looks for the /-/ that follows the package name.
func (c *Control) registryPaths(u *url.URL, path string) []string {
	out := []string{path}
	for _, t := range c.trustedOf(model.EcosystemNpm) {
		if !strings.EqualFold(t.Hostname(), u.Hostname()) {
			continue
		}
		if base := basePath(t); base != "" {
			if rest, ok := strings.CutPrefix(path, base+"/"); ok {
				out = append(out, rest)
			}
		}
	}
	return out
}

// githubPackagesPath reports whether path is download/<name>/<version>/<hash>
// for the package name.
func githubPackagesPath(path, name string) bool {
	rest, ok := strings.CutPrefix(path, "download/"+name+"/")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] != ""
}

// trustedOf returns the trusted registries of an ecosystem: its public
// registries and the user registries.
func (c *Control) trustedOf(eco model.Ecosystem) []*url.URL {
	if t, ok := c.trusted[eco]; ok {
		return t
	}
	return c.user
}

// OptionsSchema returns the JSON Schema of the options.
func (c *Control) OptionsSchema() []byte { return optschema.Of(&Options{}) }

var (
	_ plugin.Control   = (*Control)(nil)
	_ plugin.Describer = (*Control)(nil)
	_ plugin.Schemer   = (*Control)(nil)
)
