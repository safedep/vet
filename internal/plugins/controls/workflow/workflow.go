// Package workflow holds the GitHub Actions workflow controls: a dangerous
// trigger with a checkout of the pull request, template injection, and an
// action that is not pinned to a commit SHA.
package workflow

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the plugin name and the config key under plugins.
const Name = "workflow"

// Control ids.
const (
	IDDangerousTrigger  = "dangerous-trigger"
	IDTemplateInjection = "template-injection"
	IDUnpinnedAction    = "unpinned-action"
)

const fixCommand = "vet fix github-actions run"

// Options are plugins.workflow.options.
type Options struct {
	// AllowUnpinned lists the actions that can use a tag, such as
	// "my-org/*" or "actions/checkout". A pattern matches the action name,
	// or its owner/repo part, with path.Match.
	AllowUnpinned []string `json:"allow_unpinned"`
}

// Control evaluates the workflow files.
type Control struct {
	allow []string
}

// New builds the control from its options.
func New(cfg plugin.Config) (plugin.Control, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	for _, p := range o.AllowUnpinned {
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("workflow: allow_unpinned pattern %q: %w", p, err)
		}
	}
	return &Control{allow: o.AllowUnpinned}, nil
}

var infos = map[string]plugin.ControlInfo{
	IDDangerousTrigger: {
		ID: IDDangerousTrigger, Family: finding.FamilyWorkflow, Severity: finding.SeverityHigh,
		Title:       "Dangerous workflow trigger",
		Description: "A pull_request_target or workflow_run workflow checks out the code of the pull request. That code runs with the secrets and the write token of the base repository.",
	},
	IDTemplateInjection: {
		ID: IDTemplateInjection, Family: finding.FamilyWorkflow, Severity: finding.SeverityHigh,
		Title:       "Workflow template injection",
		Description: "A script interpolates an event field that an outside user controls, such as the title of a pull request. The user can run commands in the workflow.",
	},
	IDUnpinnedAction: {
		ID: IDUnpinnedAction, Family: finding.FamilyWorkflow, Severity: finding.SeverityMedium,
		Title:       "Action not pinned to a commit SHA",
		Description: "A step uses an action by a tag or a branch. The owner of the action, or an attacker who controls it, can move the tag to other code.",
	},
}

// Controls describes the control ids.
func (c *Control) Controls() []plugin.ControlInfo {
	return []plugin.ControlInfo{infos[IDDangerousTrigger], infos[IDTemplateInjection], infos[IDUnpinnedAction]}
}

// Evaluate reads the workflow file of the manifest from the target.
func (c *Control) Evaluate(_ context.Context, m *model.Manifest, _ plugin.State) ([]finding.Finding, error) {
	if m.Kind != model.ManifestKindWorkflow || m.Root == nil {
		return nil, nil
	}
	data, err := fs.ReadFile(m.Root, m.Path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", m.Path, err)
	}
	d := parse(data)
	if d == nil {
		return nil, nil
	}
	e := &emitter{path: m.Path, doc: d, seen: map[string]int{}}
	c.dangerousTrigger(e)
	c.templateInjection(e)
	c.unpinned(e)
	return e.out, nil
}

// emitter builds the file findings of one file, with the occurrence index
// among identical snippets.
type emitter struct {
	path string
	doc  *document
	seen map[string]int
	out  []finding.Finding
}

func (e *emitter) add(id string, l int, discriminator, title string, rem *finding.Remediation) {
	snippet := e.doc.text(l)
	k := strings.Join([]string{id, discriminator, finding.NormalizeSnippet(snippet)}, "\x00")
	occ := e.seen[k]
	e.seen[k]++
	info := infos[id]
	f := finding.ForFile(finding.Meta{
		ControlID: id, Family: info.Family, Severity: info.Severity,
		Title: title, Description: info.Description,
	}, finding.Locus{Path: e.path, StartLine: l, EndLine: l, Snippet: snippet},
		finding.Key{Discriminator: discriminator, Occurrence: occ})
	f.Remediation = rem
	e.out = append(e.out, f)
}

func (c *Control) dangerousTrigger(e *emitter) {
	triggers := e.doc.triggers()
	var trigger string
	for _, t := range dangerousTriggers {
		if slices.Contains(triggers, t) {
			trigger = t
			break
		}
	}
	if trigger == "" {
		return
	}
	rem := &finding.Remediation{Summary: "Check out the base commit, or move the steps that run the pull request code to a pull_request workflow with no secrets."}
	for _, s := range e.doc.steps() {
		var at *yaml.Node
		if strings.HasPrefix(scalar(get(s.node, "uses")), checkoutUsing) {
			with := get(s.node, "with")
			for _, key := range []string{"ref", "repository"} {
				if v := get(with, key); readsHead(scalar(v)) {
					at = v
					break
				}
			}
		}
		if run := get(s.node, "run"); at == nil && checkoutCommand.MatchString(scalar(run)) &&
			(readsHead(scalar(run)) || strings.Contains(scalar(run), "gh pr checkout")) {
			at = run
		}
		if at == nil {
			continue
		}
		e.add(IDDangerousTrigger, line(at, 0), s.job,
			fmt.Sprintf("%s with a checkout of the pull request code in job %s", trigger, s.job), rem)
	}
}

func (c *Control) templateInjection(e *emitter) {
	for _, s := range e.doc.steps() {
		for _, script := range scripts(s) {
			for _, loc := range expression.FindAllStringSubmatchIndex(script.Value, -1) {
				for _, field := range untrusted(script.Value[loc[2]:loc[3]]) {
					e.add(IDTemplateInjection, line(script, loc[0]), field,
						fmt.Sprintf("${{ %s }} in a script", field),
						&finding.Remediation{Summary: fmt.Sprintf("Pass the value through an environment variable: set env: VALUE: ${{ %s }} on the step, and use \"$VALUE\" in the script.", field)})
				}
			}
		}
	}
}

// scripts returns the run: script of a step and the script input of
// actions/github-script.
func scripts(s step) []*yaml.Node {
	var out []*yaml.Node
	if run := get(s.node, "run"); scalar(run) != "" {
		out = append(out, run)
	}
	if strings.HasPrefix(scalar(get(s.node, "uses")), githubScript) {
		if script := get(get(s.node, "with"), "script"); scalar(script) != "" {
			out = append(out, script)
		}
	}
	return out
}

func (c *Control) unpinned(e *emitter) {
	for _, u := range e.doc.uses() {
		value := scalar(u.node)
		if strings.Contains(value, "${{") {
			continue
		}
		name, ok := pinned(value)
		if ok || c.allowed(name) {
			continue
		}
		e.add(IDUnpinnedAction, line(u.node, 0), name, fmt.Sprintf("%s is not pinned to a commit SHA", value),
			&finding.Remediation{Summary: "Pin the action to the commit SHA of the tag, and keep the tag in a comment.", Command: fixCommand})
	}
}

func (c *Control) allowed(name string) bool {
	names := []string{name}
	if parts := strings.SplitN(name, "/", 3); len(parts) == 3 && !strings.HasPrefix(name, "docker://") {
		names = append(names, parts[0]+"/"+parts[1])
	}
	for _, p := range c.allow {
		for _, n := range names {
			if ok, err := path.Match(p, n); err == nil && ok {
				return true
			}
		}
	}
	return false
}

// OptionsSchema returns the JSON Schema of the options.
func (c *Control) OptionsSchema() []byte { return optschema.Of(&Options{}) }

var (
	_ plugin.Control   = (*Control)(nil)
	_ plugin.Describer = (*Control)(nil)
	_ plugin.Schemer   = (*Control)(nil)
)
