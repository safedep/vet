// Package agentconfig holds the controls of the agent and editor config
// files: the files in a repository or a home directory that make an editor
// or a coding agent run commands on a developer machine (control catalog,
// phase 4). In pull request mode, the engine keeps the findings of the
// files that the change adds or modifies.
package agentconfig

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/agentfiles"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the plugin name and the config key under plugins.
const Name = "agent-config"

// Control ids.
const (
	IDEditorTask        = "editor-task-command"
	IDAgentHook         = "agent-hook-command"
	IDMCPServer         = "mcp-server-added"
	IDInstructionChange = "agent-instruction-change"
	IDSuspiciousCommand = "suspicious-command"
)

// Options are plugins.agent-config.options.
type Options struct{}

// Control evaluates the agent and editor config files.
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
		ID: IDEditorTask, Family: finding.FamilyAgentConfig, Severity: finding.SeverityMedium,
		Title:       "Editor task runs a command",
		Description: "An editor task runs a shell command on the machine of each developer who opens the folder. A task with runOn: folderOpen runs with no click, so its severity is high.",
	},
	{
		ID: IDAgentHook, Family: finding.FamilyAgentConfig, Severity: finding.SeverityMedium,
		Title:       "Agent or git hook runs a command",
		Description: "A coding agent hook, a devcontainer lifecycle command or a git hook runs a command on the machine of each developer.",
	},
	{
		ID: IDMCPServer, Family: finding.FamilyAgentConfig, Severity: finding.SeverityMedium,
		Title:       "MCP server in an agent config",
		Description: "An MCP config gives the coding agent a server to run or to call. The agent sends it the data of the project.",
	},
	{
		ID: IDInstructionChange, Family: finding.FamilyAgentConfig, Severity: finding.SeverityInfo,
		Title:       "Agent instruction file",
		Description: "An instruction file tells a coding agent what to do in the project. Review it like code: it can tell the agent to run commands.",
	},
	{
		ID: IDSuspiciousCommand, Family: finding.FamilyAgentConfig, Severity: finding.SeverityCritical,
		Title:       "Suspicious command in an agent or editor config",
		Description: "A command that an editor, an agent or a git hook runs looks malicious: it runs a downloaded script, decodes a payload or reads credentials.",
	},
}

// Controls describes the control ids.
func (*Control) Controls() []plugin.ControlInfo { return infos }

// OptionsSchema returns the JSON Schema of the options.
func (*Control) OptionsSchema() []byte { return optschema.Of(&Options{}) }

// Evaluate reads the config file of the manifest from the target.
func (c *Control) Evaluate(_ context.Context, m *model.Manifest, _ plugin.State) ([]finding.Finding, error) {
	if m.Kind != model.ManifestKindAgentConfig || m.Root == nil {
		return nil, nil
	}
	t, ok := agentfiles.Classify(m.Path)
	if !ok {
		return nil, nil
	}
	data, err := fs.ReadFile(m.Root, m.Path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", m.Path, err)
	}
	e := &emitter{path: m.Path, lines: strings.Split(string(data), "\n"), seen: map[string]int{}}
	switch t {
	case agentfiles.Instructions:
		e.add(IDInstructionChange, finding.SeverityInfo, 1, "instructions", "Agent instruction file "+m.Path, nil)
		return e.out, nil
	case agentfiles.MCPConfig:
		servers, err := mcpServers(data)
		if err != nil {
			return nil, nil
		}
		for _, s := range servers {
			c.server(e, s)
		}
		return e.out, nil
	}
	cmds, err := commands(t, data)
	if err != nil {
		// A file that does not parse runs nothing in the editor either.
		return nil, nil
	}
	for _, cmd := range cmds {
		c.command(e, t, cmd)
	}
	return e.out, nil
}

func commands(t agentfiles.Type, data []byte) ([]command, error) {
	switch t {
	case agentfiles.EditorTasks:
		return editorTasks(data)
	case agentfiles.ClaudeSettings:
		return claudeHooks(data)
	case agentfiles.DevContainer:
		return devContainer(data)
	case agentfiles.GitHook:
		return gitHook(data), nil
	case agentfiles.Lefthook:
		return lefthook(data)
	}
	return nil, nil
}

func (c *Control) command(e *emitter, t agentfiles.Type, cmd command) {
	review := &finding.Remediation{Summary: "Review the command. Remove it if the project does not need it."}
	if t == agentfiles.EditorTasks {
		sev, title := finding.SeverityMedium, fmt.Sprintf("Task %q runs %s", cmd.name, short(cmd.text))
		if cmd.onOpen {
			sev, title = finding.SeverityHigh, fmt.Sprintf("Task %q runs %s when the folder opens", cmd.name, short(cmd.text))
		}
		e.add(IDEditorTask, sev, cmd.line, cmd.name, title, review)
	} else {
		e.add(IDAgentHook, finding.SeverityMedium, cmd.line, cmd.name, fmt.Sprintf("%s runs %s", cmd.name, short(cmd.text)), review)
	}
	c.suspicious(e, cmd.line, cmd.name, cmd.text)
}

func (c *Control) server(e *emitter, s server) {
	title := fmt.Sprintf("MCP server %q", s.name)
	switch {
	case s.command != "":
		title += " runs " + short(s.command)
	case s.url != "":
		title += " calls " + s.url
	}
	e.add(IDMCPServer, finding.SeverityMedium, s.line, s.name, title,
		&finding.Remediation{Summary: "Check who publishes the server and what it can read. Pin the version of the package that it runs."})
	if s.command != "" {
		c.suspicious(e, s.line, s.name, s.command)
	}
}

func (*Control) suspicious(e *emitter, line int, name, text string) {
	reason := suspiciousReason(text)
	if reason == "" {
		return
	}
	e.add(IDSuspiciousCommand, finding.SeverityCritical, line, name, fmt.Sprintf("%s %s", name, reason),
		&finding.Remediation{Summary: "Do not run the command. Remove it, and check the machines that ran it."})
}

// short cuts a command to its first 80 characters for a title.
func short(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}

// emitter builds the file findings of one file, with the occurrence index
// among identical snippets.
type emitter struct {
	path  string
	lines []string
	seen  map[string]int
	out   []finding.Finding
}

func (e *emitter) add(id string, sev finding.Severity, line int, discriminator, title string, rem *finding.Remediation) {
	snippet := ""
	if line >= 1 && line <= len(e.lines) {
		snippet = redact(strings.TrimSpace(e.lines[line-1]))
	}
	k := strings.Join([]string{id, discriminator, finding.NormalizeSnippet(snippet)}, "\x00")
	occ := e.seen[k]
	e.seen[k]++
	var info plugin.ControlInfo
	for _, i := range infos {
		if i.ID == id {
			info = i
		}
	}
	f := finding.ForFile(finding.Meta{
		ControlID: id, Family: info.Family, Severity: sev, Confidence: finding.ConfidenceHigh,
		Title: title, Description: info.Description,
	}, finding.Locus{Path: e.path, StartLine: line, EndLine: line, Snippet: snippet},
		finding.Key{Discriminator: discriminator, Occurrence: occ})
	f.Remediation = rem
	e.out = append(e.out, f)
}
