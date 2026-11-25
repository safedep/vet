package hiddencode

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
)

func TestScriptFiles(t *testing.T) {
	scripts := map[string]string{"setup": "node s.js", "a": "npm run b", "b": "node b.js"}
	cases := []struct {
		cmd  string
		want []string
	}{
		{"node api.js", []string{"api.js"}},
		{"NODE_ENV=test node --max-old-space-size=4096 ./scripts/a.js --watch", []string{"scripts/a.js"}},
		{"jest && node b.js", []string{"b.js"}},
		{"cross-env A=1 node c.js; tsx d.ts | cat", []string{"c.js", "d.ts"}},
		{"node -r ./pre.js main.js", []string{"pre.js", "main.js"}},
		{"node --import ./hook.mjs", []string{"hook.mjs"}},
		{"node --require=./api.js x.js", []string{"api.js", "x.js"}},
		{"node -r dotenv/config x.js", []string{"x.js"}},
		{"node --title x api.js", []string{"x", "api.js"}},
		{"NODE_OPTIONS=--require=./api.js jest", []string{"api.js"}},
		{"NODE_OPTIONS='-r ./a.js --max-old-space-size=1' jest", []string{"a.js"}},
		{"bun run x.ts", []string{"x.ts"}},
		{"npx tsx y.ts", []string{"y.ts"}},
		{"npx -y tsx y.ts", []string{"y.ts"}},
		{"yarn node api.js", []string{"api.js"}},
		{"exec node api.js", []string{"api.js"}},
		{"(node api.js)", []string{"api.js"}},
		{"true\nnode api.js", []string{"api.js"}},
		{"sh -c 'node api.js'", []string{"api.js"}},
		{"bash setup.sh", []string{"setup.sh"}},
		{"cd sub && node api.js", []string{"sub/api.js"}},
		{`node scripts/setup\ file.js`, []string{"scripts/setup file.js"}},
		{`n\ode api.js`, []string{"api.js"}},
		{`node "a\"b.js"`, []string{`a"b.js`}},
		{`node "a\b.js"`, []string{`a\b.js`}},
		{`node 'a\ b.js'`, []string{`a\ b.js`}},
		{"node \\\napi.js", []string{"api.js"}},
		{"cd /tmp && node api.js", nil},
		{"npm run setup", []string{"s.js"}},
		{"npm run a", nil},
		{"/usr/bin/node 'with space.js'", []string{"with space.js"}},
		{"jest --coverage", nil},
		{"echo 'node z.js'", nil},
		{"husky install", nil},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			assert.Equal(t, tc.want, scriptFiles(tc.cmd, scripts))
		})
	}
}

func TestLocalFile(t *testing.T) {
	fsys := fstest.MapFS{
		"api.js":                    {Data: []byte("x")},
		"lib/index.js":              {Data: []byte("x")},
		"apps/a/run.ts":             {Data: []byte("x")},
		"node_modules/pkg/index.js": {Data: []byte("x")},
		"link.js":                   {Data: []byte("/outside/secret.js"), Mode: fs.ModeSymlink},
		"tools/package.json":        {Data: []byte(`{"main":"setup.js"}`)},
		"tools/setup.js":            {Data: []byte("x")},
		"tools/index.js":            {Data: []byte("x")},
		"far/package.json":          {Data: []byte(`{"main":"../../outside.js"}`)},
		"far/index.js":              {Data: []byte("x")},
		"linked":                    {Data: []byte("lib"), Mode: fs.ModeSymlink},
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
		{".", "link.js", ""},
		{".", "linked/index.js", ""},
		{".", "tools", "tools/setup.js"},
		{".", "far", "far/index.js"},
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
	decoy := []byte("{\n  \"keywords\": [\"scripts\", \"test\"],\n  \"Scripts\": {\"test\": \"x\"},\n  \"scripts\": {\n    \"test\": \"jest\"\n  }\n}\n")
	assert.Equal(t, 5, scriptLine(decoy, "test"), "a keyword and a key of another case come first")
}

func TestScriptHooks(t *testing.T) {
	fsys := fstest.MapFS{"api.js": {Data: []byte("console.log(1)\n")}}
	cases := []struct {
		name, path, data string
		want             int
	}{
		{"a hook", "package.json", `{"scripts":{"pretest":"node api.js"}}`, 1},
		{"a key of another case does not hide the hook", "package.json", `{"scripts":{"pretest":"node api.js"},"Scripts":{"pretest":"echo hi"}}`, 1},
		{"a byte order mark", "package.json", "\xef\xbb\xbf" + `{"scripts":{"postinstall":"node api.js"}}`, 1},
		{"the pre script of another script", "package.json", `{"scripts":{"prebuild":"node api.js","build":"tsc"}}`, 1},
		{"the pre script of an npm command", "package.json", `{"scripts":{"prestart":"node api.js"}}`, 1},
		{"a script whose name starts with pre", "package.json", `{"scripts":{"prettier":"node api.js"}}`, 0},
		{"the test script", "package.json", `{"scripts":{"test":"node api.js"}}`, 0},
		{"a hook that runs a missing file", "package.json", `{"scripts":{"postinstall":"node gone.js"}}`, 0},
		{"a hook that runs one file twice", "package.json", `{"scripts":{"pretest":"node api.js && node api.js"}}`, 1},
		{"an endpoint file", "/home/u/app/package.json", `{"scripts":{"pretest":"node api.js"}}`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := 0
			for _, s := range hookedCode(fsys, tc.path, []byte(tc.data)) {
				if s.ID == IDScriptHook {
					n++
				}
			}
			assert.Equal(t, tc.want, n)
		})
	}
}

func TestRoutes(t *testing.T) {
	fsys := fstest.MapFS{"setup.js": {Data: []byte("1\n")}, "data.json": {Data: []byte("{}")}}
	cases := []struct {
		name, data string
		want       bool
	}{
		{"a script that runs a file", `{"scripts":{"test":"node setup.js"}}`, true},
		{"a script that runs a file that is not there", `{"scripts":{"test":"node gone.js"}}`, false},
		{"a jest key that names a file that vet does not read", `{"jest":{"setupFiles":["./data.json"]}}`, false},
		{"no script", `{"name":"app"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Routes(fsys, Hooks, "package.json", []byte(tc.data)))
		})
	}
	assert.False(t, Routes(nil, Hooks, "package.json", []byte(`{"scripts":{"test":"node setup.js"}}`)))
}

func TestHooksNeedAFileSystem(t *testing.T) {
	assert.Empty(t, Analyze(nil, Hooks, "package.json", []byte(`{"scripts":{"pretest":"node api.js"}}`)))
}
