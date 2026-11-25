package hiddencode

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
)

func TestScriptFiles(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		{"node api.js", []string{"api.js"}},
		{"NODE_ENV=test node --max-old-space-size=4096 ./scripts/a.js --watch", []string{"./scripts/a.js"}},
		{"jest && node b.js", []string{"b.js"}},
		{"cross-env A=1 node c.js; tsx d.ts | cat", []string{"c.js", "d.ts"}},
		{"node -r ./pre.js main.js", []string{"./pre.js", "main.js"}},
		{"node --import ./hook.mjs", []string{"./hook.mjs"}},
		{"bun run x.ts", []string{"x.ts"}},
		{"npx tsx y.ts", []string{"y.ts"}},
		{"/usr/bin/node 'with space.js'", []string{"with space.js"}},
		{"jest --coverage", nil},
		{"echo 'node z.js'", nil},
		{"husky install", nil},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			assert.Equal(t, tc.want, scriptFiles(tc.cmd))
		})
	}
}

func TestLocalFile(t *testing.T) {
	fsys := fstest.MapFS{
		"api.js":                    {Data: []byte("x")},
		"lib/index.js":              {Data: []byte("x")},
		"apps/a/run.ts":             {Data: []byte("x")},
		"node_modules/pkg/index.js": {Data: []byte("x")},
	}
	cases := []struct {
		dir, spec, want string
	}{
		{".", "api", "api.js"},
		{".", "./api.js", "api.js"},
		{".", "lib", "lib/index.js"},
		{"apps/a", "run", "apps/a/run.ts"},
		{"apps/a", "../../api", "api.js"},
		{".", "../outside.js", ""},
		{".", "/etc/passwd", ""},
		{".", "https://x.example/a.js", ""},
		{".", "node_modules/pkg", ""},
		{".", "missing.js", ""},
		{".", "--flag", ""},
	}
	for _, tc := range cases {
		t.Run(tc.dir+":"+tc.spec, func(t *testing.T) {
			got, ok := localFile(fsys, tc.dir, tc.spec)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.want != "", ok)
		})
	}
}

func TestScriptLine(t *testing.T) {
	data := []byte("{\n  \"name\": \"test\",\n  \"scripts\": {\n    \"build\": \"tsc\",\n    \"test\": \"jest\"\n  }\n}\n")
	assert.Equal(t, 5, scriptLine(data, "test"), "the key in scripts, not the name field")
	assert.Equal(t, 1, scriptLine(data, "pretest"))
}

func TestHooksNeedAFileSystem(t *testing.T) {
	assert.Empty(t, Analyze(nil, Hooks, "package.json", []byte(`{"scripts":{"pretest":"node api.js"}}`)))
}
