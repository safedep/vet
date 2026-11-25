// Package hiddencode holds the controls of the code that a file of a
// repository hides: code after a run of spaces in a build config, a script
// in a font or image file, invisible Unicode characters that carry a
// payload, and a script that rewrites the git history. The hidden-code
// extractor adds a manifest only for a file that shows such a sign.
package hiddencode

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"

	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/hiddencode"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/internal/technique"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the plugin name and the config key under plugins.
const Name = "hidden-code"

// Options are plugins.hidden-code.options.
type Options struct{}

// Control evaluates the files that can hide code.
type Control struct {
	mu sync.Mutex
	// parts are the parts of split payloads that Evaluate found in this
	// scan. EvaluateApplication adds them and clears the list.
	parts []part
}

// part is a part of a split payload in one file, with the change of the
// file in pull request mode.
type part struct {
	path   string
	change model.Change
	s      hiddencode.Signal
}

// New builds the control.
func New(cfg plugin.Config) (plugin.Control, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	return &Control{}, nil
}

// control is one control id of the plugin, with its remediation.
type control struct {
	plugin.ControlInfo
	remediation string
}

var controls = []control{
	{
		plugin.ControlInfo{
			ID: hiddencode.IDPaddedCode, Family: finding.FamilyHiddenCode, Severity: finding.SeverityCritical,
			Title:       "Script hidden after a run of spaces",
			Description: "A source file, a build config or an npm entry script holds a script after a long run of white space, so an editor shows a clean line. A config can also hide it after its export. A build config runs at each build, test or lint, and an npm entry script at each npm command. An npm entry script that is far larger than the published file is also a finding. PolinRider adds its loader in these ways.",
			Attack:      true,
			Technique:   technique.PaddedCode,
		},
		"Do not build or open the project. Restore the file from a clean commit, and check the machines that built it.",
	},
	{
		plugin.ControlInfo{
			ID: hiddencode.IDDisguisedScript, Family: finding.FamilyHiddenCode, Severity: finding.SeverityCritical,
			Title:       "Script in a font, image, dictionary, style sheet or source map",
			Description: "A file with the name of a font, an image, a dictionary, an SVG image, a style sheet or a source map holds a script. A task or a loader runs it with node, so the folder looks like it holds only assets. Contagious Interview repositories ship such a fake font. vet parses an SVG image, a style sheet or a source map as JavaScript. A file that node can run, with a call and a script token, gives a finding. A real asset does not parse as JavaScript. vet reads a text asset up to 32 MiB, and a larger one gives a diagnostic that vet did not check all of it. A build with no CGO reads the start of the file and its script tokens.",
			Attack:      true,
			Technique:   technique.DisguisedScript,
		},
		"Do not open the folder in an editor or run it. Remove the file, find what runs it, and check the machines that opened the folder.",
	},
	{
		plugin.ControlInfo{
			ID: hiddencode.IDUnicodePayload, Family: finding.FamilyHiddenCode, Severity: finding.SeverityCritical,
			Title:       "Payload in invisible Unicode characters",
			Description: "A file holds 16 or more variation selectors with no base character, or tag characters outside a flag emoji. Each one carries one byte of a payload, and an editor and a code review show nothing. Real text holds none. GlassWorm spreads this way, with the decoder in the same file or in another one.",
			Attack:      true,
			Technique:   technique.UnicodePayload,
		},
		"Do not run or install the code. Remove the characters and the decoder, and check the machines that ran it.",
	},
	{
		plugin.ControlInfo{
			ID: hiddencode.IDDynamicCode, Family: finding.FamilyHiddenCode, Severity: finding.SeverityHigh,
			Title:       "Build config or npm entry script that runs dynamic code",
			Description: "A build config or an npm entry script calls eval or the Function constructor, runs code with the vm module, loads a module by a name that it builds at run time, puts require, eval or Function on the global object or under another name, or starts a process with a command that it builds at run time. A config only declares settings, and a loader needs one of these to run its payload. vet also reads each file of the project that a build config loads with a plain path, and each file that an npm lifecycle script or the test script runs with node, because a loader can sit there in place of the config. vet skips a JSON file, a native addon and a WebAssembly module, which node does not run as JavaScript. In those files vet reports only eval, the Function constructor, the vm module, and require on the global object or under another name, because a build script often starts a process or loads a module by a computed name. vet reads the syntax tree, so a renamed require or a string table does not hide it. A build with no CGO skips the check. The control warns until a false-positive run on real configs shows that it can fail the attacks gate.",
		},
		"Read the code at the line. Remove it if the config does not need it, and restore the file from a clean commit if you did not write it.",
	},
	{
		plugin.ControlInfo{
			ID: hiddencode.IDDynamicCodeAdded, Family: finding.FamilyHiddenCode, Severity: finding.SeverityHigh,
			Title:       "Change that adds dynamic code to code that runs at build, test or install time",
			Description: "In pull request mode, the change brings dynamic code into a build config, into a file of the project that a build config loads, or into a file that an npm lifecycle script or the test script runs. vet reads the base version of the config or of the package.json, and of each file that it loads or runs. The base did not have this kind of dynamic code in the file. The dynamic-code control lists each call. This control marks that the change brings it in, which is the sign of a loader that a pull request adds. A policy can suppress it by path. The control warns until a false-positive run on real pull requests shows that it can fail the attacks gate.",
		},
		"Read the code that the change adds. Do not merge it, run the tests or install the project until you know what it runs.",
	},
	{
		plugin.ControlInfo{
			ID: hiddencode.IDScriptHook, Family: finding.FamilyHiddenCode, Severity: finding.SeverityMedium,
			Title:       "Change that adds an npm lifecycle script that runs a file of the project",
			Description: "In pull request mode, the change adds a script to a package.json that npm runs on its own, or makes such a script run another file. Such a script is preinstall, install, postinstall, prepare, prepack, prepublish, postpublish, pretest, posttest, or the pre or post script of another script or of an npm command. The script runs a file of the project with node, a node runner or a shell. npm runs it at each install, test or run of the other script, and the user does not see it. So a CI job that tests the pull request runs the file. vet reads the file for dynamic code when node runs it. A script that the base version of the package.json already had gives no finding.",
		},
		"Read the file that the script runs. Remove the script if the project does not need it.",
	},
	{
		plugin.ControlInfo{
			ID: hiddencode.IDFontPayload, Family: finding.FamilyHiddenCode, Severity: finding.SeverityHigh,
			Title:       "Encoded payload or script tokens in a binary font",
			Description: "A font holds a long run of hex or base64, or several script tokens, after its binary header. node cannot run such a file, but a loader can read a payload from it. vet reads a font up to 32 MiB, and a larger font is a finding too. The control warns until a false-positive run on real fonts shows that it can fail the attacks gate.",
		},
		"Compare the font with the file from its publisher. Remove it if it differs, and find the code that reads it.",
	},
	{
		plugin.ControlInfo{
			ID: hiddencode.IDSplitPayload, Family: finding.FamilyHiddenCode, Severity: finding.SeverityHigh,
			Title:       "Payload in invisible Unicode characters split across files",
			Description: "Files that each hold 4 or more variation selectors with no base character, or tag characters outside a flag emoji, hold 16 or more together. A loader can read a payload from several files, each one under the limit of one file. The control warns until a false-positive run shows that it can fail the attacks gate.",
		},
		"Show the files with the invisible characters visible. Remove the characters and the code that reads them.",
	},
	{
		plugin.ControlInfo{
			ID: hiddencode.IDInvisibleUnicode, Family: finding.FamilyHiddenCode, Severity: finding.SeverityHigh,
			Title:       "Invisible Unicode characters",
			Description: "A file holds a run of invisible characters, or code holds a bidirectional control. They can hide text from a reviewer, hide instructions from a person who reads an agent file, or show code in another order than the compiler reads it.",
		},
		"Show the file with the invisible characters visible, and remove each one that the text does not need.",
	},
	{
		plugin.ControlInfo{
			ID: hiddencode.IDHistoryRewrite, Family: finding.FamilyHiddenCode, Severity: finding.SeverityCritical,
			Title:       "Script that rewrites the git history",
			Description: "A script amends the last commit with no hooks, keeps its date, and force-pushes it, or .gitignore hides such a script. PolinRider uses it to fold its change into the last real commit of each repository on an infected machine, so the history shows no new commit.",
			Attack:      true,
			Technique:   technique.HistoryRewrite,
		},
		"Treat the machine that holds the script as infected. Compare each repository on it with its remote history, and rotate its credentials.",
	},
}

// infos are the descriptions of the control ids.
var infos = func() []plugin.ControlInfo {
	out := make([]plugin.ControlInfo, len(controls))
	for i, c := range controls {
		out[i] = c.ControlInfo
	}
	return out
}()

// Controls describes the control ids.
func (*Control) Controls() []plugin.ControlInfo { return infos }

// OptionsSchema returns the JSON Schema of the options.
func (*Control) OptionsSchema() []byte { return optschema.Of(&Options{}) }

// Evaluate reads the file of the manifest and reports each sign of hidden
// code. A part of a split payload waits for EvaluateApplication. In pull
// request mode, Evaluate also reads the base version of the file. Each
// file whose dynamic code the base did not have gives dynamic-code-added,
// and each script hook that the base did not have gives
// script-hook-added. A full scan has no base, so it gives neither.
//
// Several configs can load one file. Each one gives the same findings on
// that file, with the same ids, and the scan keeps one of each.
func (c *Control) Evaluate(_ context.Context, m *model.Manifest, _ plugin.State) ([]finding.Finding, error) {
	signals, err := signalsOf(m.Root, m)
	if err != nil {
		return nil, err
	}
	base := baseKeys(m)
	seen := map[string]int{}
	added := map[string]bool{}
	var out []finding.Finding
	for _, s := range signals {
		if s.ID == hiddencode.IDSplitPayload {
			c.mu.Lock()
			c.parts = append(c.parts, part{m.Path, m.Change, s})
			c.mu.Unlock()
			continue
		}
		brought := base != nil && !base[signalKey(s)]
		if s.ID == hiddencode.IDScriptHook && !brought {
			continue
		}
		path := cmp.Or(s.Path, m.Path)
		title := s.Title
		if s.Campaign != "" {
			title += ". It matches " + s.Campaign
		}
		out = append(out, fileFinding(path, s, title, seen))
		if s.ID == hiddencode.IDDynamicCode && brought && !added[path] {
			added[path] = true
			a := s
			a.ID = hiddencode.IDDynamicCodeAdded
			a.Title = fmt.Sprintf("The change brings dynamic code into %s, which runs at build, test or install time", path)
			out = append(out, fileFinding(path, a, a.Title, seen))
		}
	}
	return out, nil
}

// baseKeys returns the keys of the signals of the base version of the
// file of a manifest, in pull request mode. A manifest that the change
// keeps can route to a file that the change edits, so it gets keys too. It
// returns nil in a full scan. A file that the base does not have, or that
// vet cannot read there, gives an empty set. Then each signal counts as
// new, so vet reports more, not less.
func baseKeys(m *model.Manifest) map[string]bool {
	if m.Base == nil && !m.Change.Introduces() {
		return nil
	}
	keys := map[string]bool{}
	signals, err := signalsOf(m.Base, m)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Warnf("hidden-code: read the base of %s: %v. vet takes each sign as new", m.Path, err)
		}
		return keys
	}
	for _, s := range signals {
		keys[signalKey(s)] = true
	}
	return keys
}

// signalKey is the identity of a signal across the head and the base
// version of a file. It leaves out the line and the title, which an edit
// above the signal changes.
func signalKey(s hiddencode.Signal) string {
	return s.ID + "\x00" + s.Path + "\x00" + s.Target + "\x00" + finding.NormalizeSnippet(s.Visible)
}

// EvaluateApplication adds the parts of a payload in invisible characters
// across the files of the scan. A loader can read a payload from several
// files, each one under the limit of one file. When the parts make one
// payload, each file that holds a part gets a finding. In pull request mode
// only a file that the change adds or edits gets one. The engine keeps no
// file system for a stored manifest, so Evaluate collects the parts.
func (c *Control) EvaluateApplication(context.Context, plugin.State) ([]finding.Finding, error) {
	c.mu.Lock()
	parts := c.parts
	c.parts = nil
	c.mu.Unlock()
	hidden := make([]int, len(parts))
	total := 0
	for i, p := range parts {
		hidden[i] = p.s.Hidden
		total += p.s.Hidden
	}
	if !hiddencode.SplitPayload(hidden) {
		return nil, nil
	}
	slices.SortFunc(parts, func(a, b part) int { return strings.Compare(a.path, b.path) })
	var out []finding.Finding
	for _, p := range parts {
		if p.change != model.ChangeNone && !p.change.Introduces() {
			continue
		}
		title := fmt.Sprintf("The file holds %d of the %d invisible characters of a payload that %d files split, from line %d", p.s.Hidden, total, len(parts), p.s.Line)
		out = append(out, fileFinding(p.path, p.s, title, map[string]int{}))
	}
	return out, nil
}

// signalsOf reads the file of a manifest in fsys and returns its signs of
// hidden code. A manifest of another kind, or a nil fsys, gives none.
func signalsOf(fsys fs.FS, m *model.Manifest) ([]hiddencode.Signal, error) {
	if m.Kind != model.ManifestKindFile || fsys == nil {
		return nil, nil
	}
	c, ok := hiddencode.Classify(m.Path)
	if !ok {
		return nil, nil
	}
	data, err := hiddencode.Open(fsys, m.Path, c)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", m.Path, err)
	}
	return hiddencode.Analyze(fsys, c, m.Path, data), nil
}

// fileFinding returns the finding of a signal on a file. seen counts the
// signals of one id, path and snippet, so that each one has its own id.
// The count of a routed file does not depend on the signals of the config
// that loads it, so each config gives the same ids on that file.
func fileFinding(path string, s hiddencode.Signal, title string, seen map[string]int) finding.Finding {
	info := controlOf(s.ID)
	k := s.ID + "\x00" + path + "\x00" + finding.NormalizeSnippet(s.Visible)
	occ := seen[k]
	seen[k]++
	f := finding.ForFile(finding.Meta{
		ControlID: s.ID, Family: info.Family, Severity: info.Severity, Confidence: finding.ConfidenceHigh,
		Title: title, Description: info.Description,
	}, finding.Locus{Path: path, StartLine: s.Line, EndLine: s.Line, Snippet: s.Visible},
		finding.Key{Discriminator: s.ID, Occurrence: occ})
	f.Remediation = &finding.Remediation{Summary: info.remediation}
	return f
}

// controlOf returns the control of the id of a signal. A test keeps each
// id in controls.
func controlOf(id string) control {
	return controls[slices.IndexFunc(controls, func(c control) bool { return c.ID == id })]
}
