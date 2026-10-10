// Package agentconfig holds the controls of the agent and editor config
// files: the files in a repository or a home directory that make an editor
// or a coding agent run commands on a developer machine (control catalog,
// phase 4). In pull request mode, the engine keeps the findings of the
// files that the change adds or modifies.
package agentconfig

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path"
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
	IDUnreadable        = "agent-config-unreadable"
)

const (
	// maxSize is the largest config file that the control reads. A larger
	// file gives an unreadable finding, so padding cannot push a command
	// past the limit unseen. No real config comes near 1 MiB.
	maxSize = 1 << 20
	// maxCommands is the most commands and servers that the control reads in
	// one file. The rest give one unreadable finding, so a file cannot make
	// the scan slow with many findings.
	maxCommands = 500
	// maxSnippet is the longest snippet that a finding shows. The finding id
	// still hashes the whole line.
	maxSnippet = 200
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
		Attack:      true,
	},
	{
		ID: IDUnreadable, Family: finding.FamilyAgentConfig, Severity: finding.SeverityHigh,
		Title:       "Agent or editor config that vet cannot read",
		Description: "vet cannot parse the file, or the file is too large to read, so vet cannot check what it runs. An editor or an agent can still run it, and an attacker can break or pad a file to hide a command.",
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
	data, err := readLimited(m.Root, m.Path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", m.Path, err)
	}
	e := &emitter{path: m.Path, seen: map[string]int{}, snippets: map[int]snippet{}}
	if len(data) > maxSize {
		e.unreadable(1, "size", fmt.Sprintf("%s is larger than %d MiB, the most that vet reads", m.Path, maxSize>>20))
		return e.out, nil
	}
	e.lines = strings.Split(string(data), "\n")
	if t == agentfiles.Instructions {
		e.add(IDInstructionChange, finding.SeverityInfo, 1, "instructions", "Agent instruction file "+m.Path, nil)
		return e.out, nil
	}
	cmds, servers, err := parse(t, data)
	if err != nil {
		e.unreadable(errorLine(err), "parse", fmt.Sprintf("vet cannot parse %s: %s", m.Path, short(firstLine(err.Error()))))
		return e.out, nil
	}
	if len(cmds)+len(servers) > maxCommands {
		e.unreadable(1, "count", fmt.Sprintf("%s holds more than %d commands, the most that vet reads", m.Path, maxCommands))
		cmds = cmds[:min(len(cmds), maxCommands)]
		servers = servers[:min(len(servers), maxCommands-len(cmds))]
	}
	for _, cmd := range cmds {
		c.command(e, t, cmd)
	}
	for _, s := range servers {
		c.server(e, s)
	}
	return e.out, nil
}

// readLimited reads at most one byte more than maxSize, so a file that grows
// or has no fixed size cannot make the control read more.
func readLimited(fsys fs.FS, name string) (data []byte, err error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	return io.ReadAll(io.LimitReader(f, maxSize+1))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// parse reads the commands of a file, or the servers of an MCP config.
func parse(t agentfiles.Type, data []byte) ([]command, []server, error) {
	if t == agentfiles.MCPConfig {
		servers, err := mcpServers(data)
		return nil, servers, err
	}
	cmds, err := commands(t, data)
	return cmds, nil, err
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
	reason := suspiciousReason(text, path.Base(path.Dir(e.path)))
	if reason == "" {
		return
	}
	e.add(IDSuspiciousCommand, finding.SeverityCritical, line, name, fmt.Sprintf("%s %s", name, reason),
		&finding.Remediation{Summary: "Do not run the command. Remove it, and check the machines that ran it."})
}

func (e *emitter) unreadable(line int, discriminator, title string) {
	e.add(IDUnreadable, finding.SeverityHigh, line, discriminator, title,
		&finding.Remediation{Summary: "Fix the file or remove it. An editor or an agent can run what vet cannot read."})
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
	// snippets holds the snippet of each line. One minified line can hold
	// every command of a file, so the emitter reads each line once.
	snippets map[int]snippet
}

// snippet is the redacted text of a line: the full text for the finding
// id, and a short text for display.
type snippet struct{ full, display string }

func (e *emitter) snippet(line int) snippet {
	if line < 1 || line > len(e.lines) {
		return snippet{}
	}
	s, ok := e.snippets[line]
	if !ok {
		s.full = redact(strings.TrimSpace(e.lines[line-1]))
		s.display = s.full
		if len(s.display) > maxSnippet {
			s.display = s.display[:maxSnippet-3] + "..."
		}
		e.snippets[line] = s
	}
	return s
}

func (e *emitter) add(id string, sev finding.Severity, line int, discriminator, title string, rem *finding.Remediation) {
	snip := e.snippet(line)
	k := strings.Join([]string{id, discriminator, finding.NormalizeSnippet(snip.full)}, "\x00")
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
	}, finding.Locus{Path: e.path, StartLine: line, EndLine: line, Snippet: snip.full},
		finding.Key{Discriminator: discriminator, Occurrence: occ})
	f.Locus.Snippet = snip.display
	f.Remediation = rem
	e.out = append(e.out, f)
}
