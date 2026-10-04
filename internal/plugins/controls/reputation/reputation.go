// Package reputation holds the identity and reputation controls (control
// catalog, phase 3): typosquat, a new or unpopular package, a version
// anomaly, starjacking, dependency confusion, and an AI BOM delta: a new AI
// SDK in a manifest, or a new AI capability in the code.
//
// gap G6: Insights v2 has no maintainers and no publisher of a version, so
// the maintainer change control does not exist, and starjacking cannot
// check that the publisher owns the claimed repository.
package reputation

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the plugin name and the config key under plugins.
const Name = "reputation"

// Control ids.
const (
	IDTyposquat      = "typosquat"
	IDNewPackage     = "new-unpopular-package"
	IDVersionAnomaly = "version-anomaly"
	IDStarjacking    = "starjacking"
	IDConfusion      = "dependency-confusion"
	IDAIBOM          = "ai-bom-delta"
)

const (
	defaultNewDays      = 30
	defaultMinDownloads = 1000
	// popularDownloads is the download count of a package that is popular
	// itself, so a name close to another popular name is not a squat.
	popularDownloads = 50000
	// starjackStars and starjackDownloads describe a package that claims a
	// popular repository and that few people install.
	starjackStars     = 1000
	starjackDownloads = 100
)

// publicRegistries are the hosts of the public registries, for dependency
// confusion.
var publicRegistries = []string{"registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org"}

// Options are plugins.reputation.options.
type Options struct {
	// NewPackageDays is the age in days of the first version of a new
	// package. The default is 30.
	NewPackageDays int `json:"new_package_days"`
	// MinDownloads is the download count under which a new package is
	// unpopular. The default is 1000.
	MinDownloads int64 `json:"min_downloads"`
	// InternalNames are the patterns of the names of the internal packages,
	// such as "@acme/*" or "acme-*". A package that matches and comes from
	// a public registry is a dependency confusion.
	InternalNames []string `json:"internal_names"`
}

// Control evaluates the reputation of the packages of a manifest.
type Control struct {
	o   Options
	now func() time.Time
}

// New builds the control from its options.
func New(cfg plugin.Config) (plugin.Control, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	if o.NewPackageDays <= 0 {
		o.NewPackageDays = defaultNewDays
	}
	if o.MinDownloads <= 0 {
		o.MinDownloads = defaultMinDownloads
	}
	for _, p := range o.InternalNames {
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("reputation: internal_names pattern %q: %w", p, err)
		}
	}
	return &Control{o: o, now: time.Now}, nil
}

var infos = []plugin.ControlInfo{
	{
		ID: IDTyposquat, Family: finding.FamilyReputation, Severity: finding.SeverityHigh,
		Title:       "Typosquat of a popular package",
		Description: "The name is one typo away from a popular package, and few people install it. Attackers publish such names to catch a typo.",
	},
	{
		ID: IDNewPackage, Family: finding.FamilyReputation, Severity: finding.SeverityMedium,
		Title:       "New and unpopular package",
		Description: "The first version of the package is recent, and few people install it. Nobody has had time to review it.",
	},
	{
		ID: IDVersionAnomaly, Family: finding.FamilyReputation, Severity: finding.SeverityMedium,
		Title:       "Version anomaly on an upgrade",
		Description: "The upgrade jumps two or more major versions, or the new version is older than the previous one. A takeover often publishes such a version.",
	},
	{
		ID: IDStarjacking, Family: finding.FamilyReputation, Severity: finding.SeverityMedium,
		Title:       "Package that claims a popular repository",
		Description: "The package names a popular source repository, and few people install it. The repository may not belong to the publisher.",
	},
	{
		ID: IDConfusion, Family: finding.FamilyReputation, Severity: finding.SeverityMedium,
		Title:       "Internal package name on a public registry",
		Description: "The name matches an internal package name, and the package comes from a public registry. An attacker can publish a public package with the name of an internal one.",
	},
	{
		ID: IDAIBOM, Family: finding.FamilyAIBOM, Severity: finding.SeverityMedium,
		Title:       "New AI capability",
		Description: "The change adds an LLM provider SDK, an agent framework or an MCP library, or code that calls one.",
	},
}

// Controls describes the control ids.
func (*Control) Controls() []plugin.ControlInfo { return infos }

// OptionsSchema returns the JSON Schema of the options.
func (*Control) OptionsSchema() []byte { return optschema.Of(&Options{}) }

// Evaluate checks each package of the manifest.
func (c *Control) Evaluate(_ context.Context, m *model.Manifest, _ plugin.State) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, p := range m.Packages {
		if p.Change == model.ChangeRemoved {
			continue
		}
		name := p.ID.QualifiedName()
		if target := squatOf(p); target != "" {
			out = append(out, newFinding(IDTyposquat, m, p, target,
				fmt.Sprintf("%s looks like a typo of %s", name, target),
				fmt.Sprintf("Check that you want %s and not %s.", name, target)))
		}
		if c.newAndUnpopular(p) {
			out = append(out, newFinding(IDNewPackage, m, p, "",
				newPackageTitle(name, p.Insight, c.now()),
				"Review the code of the package before you use it, or wait until it has users."))
		}
		if why := anomaly(p); why != "" {
			out = append(out, newFinding(IDVersionAnomaly, m, p, p.PreviousVersion,
				fmt.Sprintf("%s: %s", p.ID, why),
				"Check the release notes and the publisher of the version."))
		}
		// gap G6: with no publisher, the check compares the stars with the
		// downloads, so it needs a download count.
		if in := p.Insight; in != nil && in.Stars >= starjackStars && in.Downloads > 0 && in.Downloads < starjackDownloads {
			out = append(out, newFinding(IDStarjacking, m, p, in.SourceRepo,
				fmt.Sprintf("%s claims %s with %d stars and has %d downloads", name, in.SourceRepo, in.Stars, in.Downloads),
				"Check that the publisher of the package owns the repository."))
		}
		if c.confused(p) {
			out = append(out, newFinding(IDConfusion, m, p, "",
				fmt.Sprintf("%s has an internal name and comes from a public registry", name),
				"Install the package from the internal registry, and reserve the name on the public registry."))
		}
		if p.Change == model.ChangeAdded && slices.Contains(aiSDKs[p.ID.Ecosystem], name) {
			out = append(out, newFinding(IDAIBOM, m, p, "",
				fmt.Sprintf("The change adds %s", name),
				"Review the use of the AI capability against the AI policy of the project."))
		}
	}
	return out, nil
}

var _ plugin.ApplicationControl = (*Control)(nil)

// aiTag is the signature tag of an AI capability.
const aiTag = report.TagAI

// EvaluateApplication reports each AI capability that the change adds to the
// code of the application. The codeusage enricher sets the change of a
// capability in pull request mode only, so a full scan reports none.
func (c *Control) EvaluateApplication(ctx context.Context, s plugin.State) ([]finding.Finding, error) {
	var out []finding.Finding
	for capability, err := range s.Capabilities(ctx) {
		if err != nil {
			return nil, err
		}
		if capability.Change == model.ChangeAdded && capability.HasTag(aiTag) {
			out = append(out, capabilityFinding(capability))
		}
	}
	return out, nil
}

func capabilityFinding(c *report.Capability) finding.Finding {
	info := infoOf(IDAIBOM)
	name := cmp.Or(strings.TrimSpace(strings.Join([]string{c.Product, c.Service}, " ")), c.ID)
	f := finding.ForApplication(finding.Meta{
		ControlID: IDAIBOM, Family: info.Family, Severity: info.Severity,
		Title: fmt.Sprintf("The change adds a call to %s", name), Description: cmp.Or(c.Description, info.Description),
	}, ".", c.ID)
	f.Change = model.ChangeAdded
	if len(c.Occurrences) > 0 {
		o := c.Occurrences[0]
		f.Locus = &finding.Locus{Path: o.File, StartLine: o.Line, EndLine: o.Line}
		f.Evidence = []finding.Evidence{{
			Source:  "codeusage",
			Summary: fmt.Sprintf("%d calls match the code signature %s, the first in %s at line %d.", len(c.Occurrences), c.ID, o.File, o.Line),
		}}
	}
	f.Remediation = &finding.Remediation{Summary: "Review the use of the AI capability against the AI policy of the project."}
	return f
}

func infoOf(id string) plugin.ControlInfo {
	for _, i := range infos {
		if i.ID == id {
			return i
		}
	}
	return plugin.ControlInfo{}
}

// newAndUnpopular fails open: a package with no publish date is not new.
// A new package with no download count is new and unpopular, because the
// age is the stronger sign. A new package of an established publisher is
// not unpopular.
func (c *Control) newAndUnpopular(p *model.Package) bool {
	in := p.Insight
	if in == nil || in.FirstPublishedAt == nil || ownScope(p) {
		return false
	}
	age := c.now().Sub(*in.FirstPublishedAt)
	return age >= 0 && age < time.Duration(c.o.NewPackageDays)*24*time.Hour && in.Downloads < c.o.MinDownloads
}

// ownScope reports an npm package whose scope is the owner of its popular
// source repository, such as @pnpm/exe.linux-x64 from pnpm/pnpm. Only the
// owner of a scope publishes to it, so a new platform package of a known
// project is not an unknown package.
func ownScope(p *model.Package) bool {
	in := p.Insight
	if p.ID.Ecosystem != model.EcosystemNpm || p.ID.Namespace == "" || in.Stars < starjackStars {
		return false
	}
	owner, ok := repoOwner(in.SourceRepo)
	return ok && strings.EqualFold(strings.TrimPrefix(p.ID.Namespace, "@"), owner)
}

// repoOwner returns the owner of a github.com repository URL.
func repoOwner(repo string) (string, bool) {
	u, err := url.Parse(repo)
	if err != nil || !strings.EqualFold(u.Host, "github.com") {
		return "", false
	}
	owner, _, ok := strings.Cut(strings.Trim(u.Path, "/"), "/")
	return owner, ok && owner != ""
}

func newPackageTitle(name string, in *model.Insight, now time.Time) string {
	days := int(now.Sub(*in.FirstPublishedAt).Hours() / 24)
	if in.Downloads == 0 {
		return fmt.Sprintf("%s is new: its first version is %d days old", name, days)
	}
	return fmt.Sprintf("%s is new: its first version is %d days old, with %d downloads", name, days, in.Downloads)
}

func (c *Control) confused(p *model.Package) bool {
	name := p.ID.QualifiedName()
	internal := false
	for _, pat := range c.o.InternalNames {
		if ok, _ := path.Match(pat, name); ok {
			internal = true
			break
		}
	}
	if !internal {
		return false
	}
	if p.Resolved == "" {
		// With no resolved URL, the public registry knows the package when
		// Insights has data for it.
		return p.Insight != nil
	}
	u, err := url.Parse(p.Resolved)
	return err == nil && slices.Contains(publicRegistries, strings.ToLower(u.Hostname()))
}

// anomaly returns why an upgrade looks wrong, or "".
func anomaly(p *model.Package) string {
	if p.Change != model.ChangeUpgraded || p.PreviousVersion == "" {
		return ""
	}
	if from, to, ok := majors(p.PreviousVersion, p.ID.Version); ok && to-from >= 2 {
		return fmt.Sprintf("the upgrade jumps from %s to %s", p.PreviousVersion, p.ID.Version)
	}
	in, prev := p.Insight, p.PreviousInsight
	if in != nil && prev != nil && in.PublishedAt != nil && prev.PublishedAt != nil && in.PublishedAt.Before(*prev.PublishedAt) {
		return fmt.Sprintf("the registry published it before %s", p.PreviousVersion)
	}
	return ""
}

func majors(from, to string) (int, int, bool) {
	a, okA := major(from)
	b, okB := major(to)
	return a, b, okA && okB
}

func major(v string) (int, bool) {
	v = strings.TrimPrefix(v, "v")
	head, _, _ := strings.Cut(v, ".")
	n, err := strconv.Atoi(head)
	return n, err == nil
}

func newFinding(id string, m *model.Manifest, p *model.Package, discriminator, title, fix string) finding.Finding {
	info := infoOf(id)
	f := finding.ForPackage(finding.Meta{
		ControlID: id, Family: info.Family, Severity: info.Severity, Confidence: finding.ConfidenceMedium,
		Title: title, Description: info.Description,
	}, m.Path, p, finding.Key{Discriminator: discriminator})
	f.Remediation = &finding.Remediation{Summary: fix}
	return f
}
