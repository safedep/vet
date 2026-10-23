package prcomment

import (
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/safedep/dry/log"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/finding"
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
	// maxAgentIDs bounds each list of finding ids in the agent block.
	maxAgentIDs = 100
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
	// Other holds the ids of the findings that the comment shows in its
	// closed list.
	Other []string `yaml:"other,omitempty,flow"`
}

type agentCause struct {
	Gate         string   `yaml:"gate"`
	Control      string   `yaml:"control"`
	Rules        []string `yaml:"rules,omitempty,flow"`
	FailOn       string   `yaml:"fail_on,omitempty"`
	Subject      string   `yaml:"subject"`
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
	for _, g := range slices.Concat(sec.shown, sec.attacks) {
		block.Causes = append(block.Causes, cause(g))
	}
	block.Other = capIDs(ids(sec.rest))
	var data strings.Builder
	enc := yaml.NewEncoder(&data)
	enc.SetIndent(2)
	if err := enc.Encode(block); err != nil {
		log.Warnf("pr-comment: write the agent block: %v", err)
		return
	}
	c.open(b, "For AI agents")
	fmt.Fprintf(b, "```yaml\n%s```\n\n", fenceSafe(data.String()))
	c.close(b)
}

func cause(g render.Group) agentCause {
	f := g.Lead()
	out := agentCause{Gate: "none", Control: f.ControlID, Subject: render.SubjectID(f), Place: render.Where(f), Fix: g.Fix(), Findings: capIDs(ids(g.Findings))}
	if gr := f.Gate; gr != nil {
		out.Gate, out.Rules, out.FailOn = string(gr.Action), gr.Rules, gr.FailOn
	}
	if r := f.Remediation; r != nil {
		out.FixedVersion, out.Command = render.Text(r.FixedVersion), render.Text(r.Command)
	}
	if until, ok := g.WaitUntil(); ok {
		out.WaitUntil = until.UTC().Format(time.RFC3339)
	}
	return out
}

func capIDs(ids []string) []string { return ids[:min(len(ids), maxAgentIDs)] }

// fenceSafe keeps text from the scanned code from closing the code block.
func fenceSafe(s string) string { return strings.ReplaceAll(s, "`", "'") }

// annotations are the error annotations of the blocking causes, at most
// maxAnnotations, each at the line of the lead of the cause.
func (c *input) annotations() []ci.Annotation {
	sec := c.sections()
	if !sec.blocking || c.links.NoFiles {
		return nil
	}
	var out []ci.Annotation
	for _, g := range sec.shown {
		if len(out) == maxAnnotations {
			break
		}
		f := g.Lead()
		path, line := placeOfFinding(f)
		if path == "" || !fs.ValidPath(c.links.Prefix+path) {
			continue
		}
		title := "vet: " + render.Title(f)
		text := render.Subject(f) + g.More()
		if fix := g.Fix(); fix != "" {
			text += ": " + fix
		}
		out = append(out, ci.Annotation{Path: c.links.Prefix + path, Line: line, Title: render.Truncate(title, maxField), Text: render.Truncate(text, maxText)})
	}
	return out
}

// placeOfFinding is the file and the line to edit for a finding.
func placeOfFinding(f *finding.Finding) (string, int) {
	if l := f.Locus; l != nil && l.Path != "" {
		return l.Path, l.StartLine
	}
	return f.Path(), 0
}
