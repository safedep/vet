package hygiene

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

// nonRegistrySource returns the git or file source of a lockfile entry,
// or "". An HTTP registry URL is the lockfile control's concern.
func nonRegistrySource(resolved string) string {
	if projectRoot(resolved) {
		return ""
	}
	for _, prefix := range []string{"git+", "git:", "github:", "file:", "link:", "path:"} {
		if strings.HasPrefix(resolved, prefix) {
			return resolved
		}
	}
	return ""
}

var extras = regexp.MustCompile(`\[[^\]]*\]$`)

// projectRoot reports a source that is the project itself, such as
// "file:." in a lockfile or "-e .[dev]" in a requirements file. The
// project installs its own code, which is not a dependency.
func projectRoot(spec string) bool {
	s := strings.TrimSpace(spec)
	s = strings.TrimSpace(strings.TrimPrefix(s, "-e"))
	s = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(s, "file:"), "path:"), "link:")
	s = extras.ReplaceAllString(strings.TrimSpace(s), "")
	return s == "." || s == "./"
}

// npmManifests are the npm files whose package.json declares the
// dependencies. vet reads the package.json next to each of them once.
var npmManifests = map[string]bool{
	"package.json": true, "package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "bun.lock": true,
}

// nonRegistrySpec matches an npm dependency spec that is not a registry
// version: git, a URL, a file or a link, or any version.
var nonRegistrySpec = regexp.MustCompile(`^(git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:)|^(\*|latest|x|)$`)

// declaredNonRegistry reads the file that declares the dependencies of the
// manifest, and reports each dependency that is not on a registry.
func declaredNonRegistry(m *model.Manifest) ([]finding.Finding, error) {
	if m.Root == nil {
		return nil, nil
	}
	base := path.Base(m.Path)
	switch {
	case npmManifests[base]:
		return packageJSON(m, path.Join(path.Dir(m.Path), "package.json"))
	case m.Extractor == "python/requirements":
		return requirements(m)
	}
	return nil, nil
}

func packageJSON(m *model.Manifest, p string) ([]finding.Finding, error) {
	data, err := fs.ReadFile(m.Root, p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	var pj struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		// A package.json that does not parse installs nothing.
		return nil, nil
	}
	var out []finding.Finding
	for _, deps := range []map[string]string{pj.Dependencies, pj.DevDependencies, pj.OptionalDependencies} {
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			spec := strings.TrimSpace(deps[n])
			if !nonRegistrySpec.MatchString(spec) {
				continue
			}
			out = append(out, fileFinding(p, data, n, spec))
		}
	}
	return out, nil
}

// requirementSource matches a requirements.txt line that installs from
// git, a URL or a path.
var requirementSource = regexp.MustCompile(`(?i)(git\+|https?://|file:|^-e\s+[./]|^\.{0,2}/)`)

func requirements(m *model.Manifest) ([]finding.Finding, error) {
	data, err := fs.ReadFile(m.Root, m.Path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", m.Path, err)
	}
	var out []finding.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "--") {
			continue
		}
		if requirementSource.MatchString(line) && !projectRoot(line) {
			out = append(out, fileFinding(m.Path, data, line, line))
		}
	}
	return out, sc.Err()
}

func fileFinding(p string, data []byte, name, spec string) finding.Finding {
	line, snippet := 1, ""
	if i := bytes.Index(data, []byte(name)); i >= 0 {
		line = bytes.Count(data[:i], []byte("\n")) + 1
		snippet = strings.TrimSpace(strings.Split(string(data), "\n")[line-1])
	}
	info := infos[4]
	f := finding.ForFile(finding.Meta{
		ControlID: IDNonRegistry, Family: info.Family, Severity: info.Severity, Confidence: finding.ConfidenceHigh,
		Title: fmt.Sprintf("%s comes from %s", name, describe(spec)), Description: info.Description,
	}, finding.Locus{Path: p, StartLine: line, EndLine: line, Snippet: snippet}, finding.Key{Discriminator: name})
	f.Remediation = &finding.Remediation{Summary: "Use a released version from a registry, or pin the source to a commit."}
	return f
}

func describe(spec string) string {
	switch spec {
	case "", "*", "x", "latest":
		return "any version (" + strings.TrimSpace(spec+" ") + ")"
	}
	return spec
}
