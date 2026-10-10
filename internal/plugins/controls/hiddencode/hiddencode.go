// Package hiddencode holds the controls of the code that a file of a
// repository hides: code after a run of spaces in a build config, a script
// in a font or image file, invisible Unicode characters that carry a
// payload, and a script that rewrites the git history. The hidden-code
// extractor adds a manifest only for a file that shows such a sign.
package hiddencode

import (
	"context"
	"fmt"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/hiddencode"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the plugin name and the config key under plugins.
const Name = "hidden-code"

// Options are plugins.hidden-code.options.
type Options struct{}

// Control evaluates the files that can hide code.
type Control struct{}

// New builds the control.
func New(cfg plugin.Config) (plugin.Control, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	return &Control{}, nil
}

var infos = []plugin.ControlInfo{
	{
		ID: hiddencode.IDPaddedCode, Family: finding.FamilyHiddenCode, Severity: finding.SeverityCritical,
		Title:       "Code hidden in a build config",
		Description: "A build or tool config holds code after a long run of spaces or after its export, so an editor shows a clean file. The config runs at each build, test or lint. PolinRider adds its loader this way.",
		Attack:      true,
	},
	{
		ID: hiddencode.IDDisguisedScript, Family: finding.FamilyHiddenCode, Severity: finding.SeverityCritical,
		Title:       "Script in a font, image or dictionary file",
		Description: "A file with the name of a font, an image or a dictionary holds a script. A task or a loader runs it with node, so the folder looks like it holds only assets. Contagious Interview repositories ship such a fake font.",
		Attack:      true,
	},
}

// Controls describes the control ids.
func (*Control) Controls() []plugin.ControlInfo { return infos }

// OptionsSchema returns the JSON Schema of the options.
func (*Control) OptionsSchema() []byte { return optschema.Of(&Options{}) }

var remediation = map[string]string{
	hiddencode.IDPaddedCode:      "Do not build or open the project. Restore the file from a clean commit, and check the machines that built it.",
	hiddencode.IDDisguisedScript: "Do not open the folder in an editor or run it. Remove the file, find what runs it, and check the machines that opened the folder.",
}

// Evaluate reads the file of the manifest and reports each sign of hidden
// code.
func (*Control) Evaluate(_ context.Context, m *model.Manifest, _ plugin.State) ([]finding.Finding, error) {
	if m.Kind != model.ManifestKindFile || m.Root == nil {
		return nil, nil
	}
	c, ok := hiddencode.Classify(m.Path)
	if !ok {
		return nil, nil
	}
	data, err := hiddencode.Read(m.Root, m.Path, c)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", m.Path, err)
	}
	seen := map[string]int{}
	var out []finding.Finding
	for _, s := range hiddencode.Analyze(c, m.Path, data) {
		info := infoOf(s.ID)
		title := s.Title
		if s.Campaign != "" {
			title += ". It matches " + s.Campaign
		}
		k := s.ID + "\x00" + finding.NormalizeSnippet(s.Visible)
		occ := seen[k]
		seen[k]++
		f := finding.ForFile(finding.Meta{
			ControlID: s.ID, Family: info.Family, Severity: info.Severity, Confidence: finding.ConfidenceHigh,
			Title: title, Description: info.Description,
		}, finding.Locus{Path: m.Path, StartLine: s.Line, EndLine: s.Line, Snippet: s.Visible},
			finding.Key{Discriminator: s.ID, Occurrence: occ})
		f.Remediation = &finding.Remediation{Summary: remediation[s.ID]}
		out = append(out, f)
	}
	return out, nil
}

func infoOf(id string) plugin.ControlInfo {
	for _, i := range infos {
		if i.ID == id {
			return i
		}
	}
	return plugin.ControlInfo{ID: id, Family: finding.FamilyHiddenCode, Severity: finding.SeverityHigh}
}
