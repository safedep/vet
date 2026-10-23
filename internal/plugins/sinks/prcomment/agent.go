package prcomment

import (
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/safedep/dry/log"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/internal/ci"
	"github.com/safedep/vet/v2/internal/plugins/internal/render"
)

const (
	// agentVersion is the version of the agent block. A change that
	// renames or removes a key bumps it.
	agentVersion = "v1"
	// reportDir is the directory that the download command writes the
	// report to.
	reportDir = "vet-report"
	// maxAgentIDs bounds each list of finding ids in the agent block, and
	// maxAgentCauses its causes.
	maxAgentIDs    = 100
	maxAgentCauses = 50
	// maxAnnotations bounds the annotations of a run.
	maxAnnotations = 10
)

// agentBlock is the data of the comment for a coding agent: what blocks,
// the fix of each cause as data, and the commands that read the full
// report. docs/github-action.md documents the keys.
type agentBlock struct {
	Version string       `yaml:"vet-agent"`
	Gate    string       `yaml:"gate"`
	Head    string       `yaml:"head,omitempty"`
	Report  string       `yaml:"report,omitempty"`
	Finding string       `yaml:"finding,omitempty"`
	Causes  []agentCause `yaml:"causes,omitempty"`
	// More counts the causes past maxAgentCauses. The report has them.
	More int `yaml:"more,omitempty"`
	// Other holds the ids of the findings that the comment shows in its
	// closed list.
	Other []string `yaml:"other,omitempty,flow"`
}

type agentCause struct {
	Gate         string   `yaml:"gate"`
	Control      string   `yaml:"control"`
	Rules        []string `yaml:"rules,omitempty,flow"`
	FailOn       string   `yaml:"fail_on,omitempty"`
	Subject      string   `yaml:"subject,omitempty"`
	Place        string   `yaml:"place,omitempty"`
	Fix          string   `yaml:"fix,omitempty"`
	FixedVersion string   `yaml:"fixed_version,omitempty"`
	Command      string   `yaml:"command,omitempty"`
	WaitUntil    string   `yaml:"wait_until,omitempty"`
	Findings     []string `yaml:"findings,flow"`
}

// agent writes the closed agent block.
func (c *input) agent(b *strings.Builder, sec sections) {
	block := agentBlock{Version: agentVersion, Gate: strings.ToLower(string(c.trailer.Gate.Outcome)), Head: c.head()}
	if cmd := c.download(); cmd != "" {
		block.Report = cmd
		block.Finding = fmt.Sprintf("vet report finding show <id> --scan %s/report.json -o json", reportDir)
	}
	all := slices.Concat(sec.shown, sec.attacks)
	for _, g := range all[:min(len(all), maxAgentCauses)] {
		block.Causes = append(block.Causes, cause(g))
	}
	block.More = len(all) - len(block.Causes)
	block.Other = capIDs(ids(sec.rest))
	var data strings.Builder
	enc := yaml.NewEncoder(&data)
	enc.SetIndent(2)
	if err := enc.Encode(block); err != nil {
		log.Warnf("pr-comment: write the agent block: %v", err)
		return
	}
	// No value holds a line break and the encoder does not wrap, so no text
	// from the scanned code starts a line. The longer fence also keeps a
	// value from closing the block.
	c.open(b, "For AI agents")
	fmt.Fprintf(b, "````yaml\n%s````\n\n", data.String())
	c.close(b)
}

func cause(g render.Group) agentCause {
	f := g.Lead()
	out := agentCause{Gate: "none", Control: f.ControlID, Subject: render.SubjectID(f), Place: render.Where(f), Findings: capIDs(ids(g.Findings))}
	if gr := f.Gate; gr != nil {
		out.Gate, out.Rules, out.FailOn = string(gr.Action), gr.Rules, gr.FailOn
	}
	if r := f.Remediation; r != nil {
		out.Fix, out.FixedVersion, out.Command = render.Text(r.Summary), render.Text(r.FixedVersion), render.Text(r.Command)
	}
	out.WaitUntil = g.WaitUntilText()
	return out
}

func capIDs(ids []string) []string { return ids[:min(len(ids), maxAgentIDs)] }

// annotations mark the causes that the comment shows, at most
// maxAnnotations, each at the line of its lead: an error for a cause that
// fails the gate, and a warning for an attack that the gate does not fail.
func (c *input) annotations() []ci.Annotation {
	if c.links.NoFiles {
		return nil
	}
	sec := c.sections()
	type marked struct {
		g     render.Group
		level ci.AnnotationLevel
	}
	var gs []marked
	if sec.blocking {
		for _, g := range sec.shown {
			gs = append(gs, marked{g, ci.AnnotationError})
		}
	}
	for _, g := range sec.attacks {
		gs = append(gs, marked{g, ci.AnnotationWarning})
	}
	var out []ci.Annotation
	for _, m := range gs {
		if len(out) == maxAnnotations {
			break
		}
		f := m.g.Lead()
		path, line := render.Place(f)
		if path == "" || !fs.ValidPath(c.links.Prefix+path) {
			continue
		}
		text := render.Subject(f) + m.g.More()
		if fix := m.g.Fix(); fix != "" {
			text += ": " + fix
		}
		out = append(out, ci.Annotation{
			Level: m.level, Path: c.links.Prefix + path, Line: line,
			Title: render.Truncate("vet: "+render.Title(f), maxField), Text: render.Truncate(text, maxText),
		})
	}
	return out
}
