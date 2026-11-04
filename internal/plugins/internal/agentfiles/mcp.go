package agentfiles

import (
	"path"
	"strings"
)

// Format is the syntax of an MCP config file.
type Format int

const (
	// JSON is JSON with comments and trailing commas.
	JSON Format = iota
	TOML
	YAML
)

// MCPLayout says where an MCP config file keeps its servers.
type MCPLayout struct {
	Format Format
	// Sections are the key paths to the servers. A section holds an object
	// of server names, or a list of servers with a name key. "*" stands for
	// each key of an object.
	Sections [][]string
	// Skip holds the server types that run inside the agent, not as a
	// command or a remote server.
	Skip map[string]bool
	// MaxSize is the largest file that the control reads, or 0 for the
	// default.
	MaxSize int64
}

var standardMCP = MCPLayout{Format: JSON, Sections: [][]string{{"mcpServers"}, {"servers"}}}

// mcpFiles is the one list of the MCP config files that an agent reads,
// with the layout of each. The endpoint discovery in internal/endpoint/aitool
// reads the same files. TestDiscoveredMCPFilesClassify fails when the two
// drift apart.
//
// Known uncovered cases: CODEX_HOME and COPILOT_HOME can move the config
// folder to any path, which no name here matches. The legacy Continue
// config.json, the mcp.servers key of old VS Code settings and the
// context_servers of a Zed project settings file are not read.
var mcpFiles = []struct {
	match  func(p string) bool
	layout MCPLayout
}{
	{baseIs(".mcp.json"), standardMCP},
	{oneOf(
		suffix(".cursor", "mcp.json"),
		suffix(".vscode", "mcp.json"), suffix(".vscode", "mcpservers.json"), suffix(".vscode", "mcp_config.json"),
		suffix("windsurf", "mcp_config.json"),
		suffix(".gemini", "settings.json"), suffix(".gemini", "antigravity", "mcp_config.json"),
		suffix(".qwen", "settings.json"),
		suffix(".github", "mcp.json"),
		suffix(".roo", "mcp.json"),
		suffix(".amazonq", "mcp.json"), suffix(".aws", "amazonq", "mcp.json"),
		suffix(".junie", "mcp", "mcp.json"),
		suffix(".kiro", "settings", "mcp.json"),
		suffix(".copilot", "mcp-config.json"),
		suffix(".augment", "settings.json"),
		suffix("settings", "cline_mcp_settings.json"),
		suffix("rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
		func(p string) bool { return path.Base(p) == "mcp.json" && isEditorUserDir(path.Dir(p)) },
	), standardMCP},
	{claudeSettings, MCPLayout{Format: JSON, Sections: [][]string{{"mcpServers"}}}},
	// Claude Code keeps the history of each project in ~/.claude.json, so
	// the file often holds many MiB. The control reads it in one pass. A
	// repository can hold a .claude.json too. Claude Code does not read it
	// there, but the name gives no way to tell the two apart.
	{baseIs(".claude.json"), MCPLayout{Format: JSON, Sections: [][]string{{"mcpServers"}, {"projects", "*", "mcpServers"}}, MaxSize: 64 << 20}},
	{suffix(".codex", "config.toml"), MCPLayout{Format: TOML, Sections: [][]string{{"mcp_servers"}}}},
	{oneOf(
		suffix(".continue", "config.yaml"),
		func(p string) bool { return endsWith(path.Dir(p), ".continue", "mcpServers") && isYAML(p) },
	), MCPLayout{Format: YAML, Sections: [][]string{{"mcpServers"}}}},
	{oneOf(suffix(".config", "goose", "config.yaml"), suffix("Block", "goose", "config", "config.yaml")), MCPLayout{
		Format: YAML, Sections: [][]string{{"extensions"}},
		Skip: map[string]bool{"builtin": true, "platform": true, "frontend": true},
	}},
	{
		oneOf(suffix(".config", "zed", "settings.json"), suffix("Roaming", "Zed", "settings.json")),
		MCPLayout{Format: JSON, Sections: [][]string{{"context_servers"}}},
	},
	// Amp prefixes its keys. The VS Code extension can also read the
	// nested form, so vet reads both.
	{
		oneOf(suffix(".amp", "settings.json"), suffix(".config", "amp", "settings.json"), suffix(".config", "amp", "settings.jsonc")),
		MCPLayout{Format: JSON, Sections: [][]string{{"amp.mcpServers"}, {"amp", "mcpServers"}}},
	},
	{oneOf(baseIs("opencode.json"), baseIs("opencode.jsonc")), MCPLayout{Format: JSON, Sections: [][]string{{"mcp"}}}},
}

// MCP returns the layout of an MCP config file, by its slash path relative
// to the target. A Claude settings file holds MCP servers too, so ok is true
// for it, while Classify gives it the type ClaudeSettings.
func MCP(p string) (MCPLayout, bool) {
	for _, f := range mcpFiles {
		if f.match(p) {
			return f.layout, true
		}
	}
	return MCPLayout{}, false
}

func isMCP(p string) bool {
	_, ok := MCP(p)
	return ok
}

// endsWith reports whether the slash path p ends with the elements elem.
func endsWith(p string, elem ...string) bool {
	return strings.HasSuffix("/"+p, "/"+strings.Join(elem, "/"))
}

func suffix(elem ...string) func(string) bool {
	return func(p string) bool { return endsWith(p, elem...) }
}

func baseIs(name string) func(string) bool {
	return func(p string) bool { return path.Base(p) == name }
}

func oneOf(fs ...func(string) bool) func(string) bool {
	return func(p string) bool {
		for _, f := range fs {
			if f(p) {
				return true
			}
		}
		return false
	}
}

// claudeSettings matches the Claude Code settings files: settings.json and
// settings.local.json in .claude, and ~/.claude/projects/<project>/settings.json.
var claudeSettings = oneOf(suffix(".claude", "settings.json"), suffix(".claude", "settings.local.json"),
	func(p string) bool {
		return path.Base(p) == "settings.json" && endsWith(path.Dir(path.Dir(p)), ".claude", "projects")
	})

func isYAML(p string) bool {
	ext := path.Ext(p)
	return ext == ".yaml" || ext == ".yml"
}
