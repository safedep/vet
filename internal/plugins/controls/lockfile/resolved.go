package lockfile

import (
	"fmt"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

// resolvedEntries checks the resolved URL that a yarn, pnpm, bun, uv or
// Cargo lockfile records for each package. A git or file source is not a
// registry: the non-registry dependency control reports it.
func (c *Control) resolvedEntries(m *model.Manifest) []finding.Finding {
	var out []finding.Finding
	for _, p := range m.Packages {
		raw := registryURL(p.Resolved)
		if raw == "" || p.Change == model.ChangeRemoved {
			continue
		}
		name := p.ID.RawName()
		key := finding.Key{Discriminator: raw}
		if !c.trustedSource(p.ID.Ecosystem(), raw) {
			out = append(out, c.packageFinding(IDUntrustedRegistry, m, p, key,
				fmt.Sprintf("%s resolves from an untrusted host", name),
				fmt.Sprintf("The lockfile installs %s from %s. The host is not a trusted registry.", name, raw)))
			continue
		}
		if p.ID.Ecosystem() == model.EcosystemNpm && !c.followsConvention(raw, name) {
			out = append(out, c.packageFinding(IDPathMismatch, m, p, key,
				fmt.Sprintf("%s resolves from the URL of another package", name),
				fmt.Sprintf("The lockfile installs %s from %s. The URL path does not match the package name.", name, raw)))
		}
	}
	return out
}

// registryURL returns the HTTP URL of a registry source, with the
// registry+ and sparse+ prefixes of Cargo removed, or "" for a source that
// is not an HTTP URL.
func registryURL(resolved string) string {
	for _, prefix := range []string{"registry+", "sparse+"} {
		resolved = strings.TrimPrefix(resolved, prefix)
	}
	if strings.HasPrefix(resolved, "https://") || strings.HasPrefix(resolved, "http://") {
		return resolved
	}
	return ""
}

// integrity reports the entries whose hash changed with no version change.
// The engine marks them MODIFIED in pull request mode.
func (c *Control) integrity(m *model.Manifest) []finding.Finding {
	var out []finding.Finding
	for _, p := range m.Packages {
		if p.Change != model.ChangeModified || p.Integrity == p.PreviousIntegrity || p.PreviousIntegrity == "" {
			continue
		}
		name := p.ID.String()
		out = append(out, c.packageFinding(IDIntegrityChanged, m, p, finding.Key{Discriminator: p.Integrity},
			fmt.Sprintf("%s has a new integrity hash", name),
			integrityDescription(name, p)))
	}
	return out
}

func integrityDescription(name string, p *model.Package) string {
	if p.Integrity == "" {
		return fmt.Sprintf("The change keeps %s and removes its integrity hash %s. The package manager then installs the archive with no check.", name, p.PreviousIntegrity)
	}
	return fmt.Sprintf("The change keeps %s and changes its integrity hash from %s to %s. Check where the new archive comes from.", name, p.PreviousIntegrity, p.Integrity)
}

func lockfileOnly(m *model.Manifest) finding.Finding {
	f := finding.ForManifest(finding.Meta{
		ControlID: IDLockfileOnly, Family: finding.FamilyLockfile, Severity: finding.SeverityHigh,
		Confidence: finding.ConfidenceLow,
		Title:      fmt.Sprintf("%s changed with no change to its manifest file", m.Path),
		Description: "The change edits the lockfile and leaves the manifest file next to it as it was. " +
			"Check that a tool made the change, for example npm update, and not a hand edit.",
	}, m.Path, m.Ecosystem, finding.Key{})
	f.Remediation = &finding.Remediation{Summary: "Regenerate the lockfile from the manifest file with the package manager, and compare."}
	return f
}

func (c *Control) packageFinding(id string, m *model.Manifest, p *model.Package, key finding.Key, title, desc string) finding.Finding {
	f := finding.ForPackage(finding.Meta{
		ControlID: id, Family: finding.FamilyLockfile, Severity: finding.SeverityHigh,
		Confidence: finding.ConfidenceMedium, Title: title, Description: desc,
	}, m.Path, p, key)
	f.Evidence = []finding.Evidence{{Source: "lockfile", Summary: p.Resolved}}
	f.References = []string{cweURL}
	f.Remediation = &finding.Remediation{
		Summary: "Make sure that the lockfile change is intended. Regenerate the lockfile from a trusted registry, or add the registry to plugins.lockfile.options.trusted_registries.",
	}
	return f
}
