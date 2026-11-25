//go:build cgo

package hiddencode

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDynamicCode(t *testing.T) {
	cases := []struct {
		name, path, data string
		want             []string
	}{
		{"eval", "vite.config.js", "eval(atob('eA=='))", []string{"eval(...)"}},
		{"indirect eval", "vite.config.js", "(0, eval)(x)", []string{"eval(...)"}},
		{"eval on the global object", "vite.config.js", "globalThis.eval(x)", []string{"eval(...)"}},
		{"indirect eval with a comment", "vite.config.js", "(0, eval /* x */)('1')", []string{"eval(...)"}},
		{"eval by a string key", "vite.config.js", "globalThis['eval']('1')", []string{"eval(...)"}},
		{"require on a global in parentheses", "vite.config.js", "(global).r = require", []string{"global[...] = ..."}},
		{"renamed require in parentheses", "vite.config.js", "const r = (require); r(x)", []string{"x = require"}},
		{"Function constructor", "vite.config.js", "new Function(x)()", []string{"Function(...)"}},
		{"Function call", "vite.config.js", "Function(x)()", []string{"Function(...)"}},
		{"Function through constructor", "vite.config.js", "[].constructor.constructor(x)()", []string{"Function(...)"}},
		{"vm", "vite.config.js", "require('vm').runInThisContext(x)", []string{"vm.runIn...(...)"}},
		{"computed require", "vite.config.js", "require('child_' + 'process')", []string{"require(<computed>)"}},
		{"computed import", "vite.config.mjs", "await import(atob(m))", []string{"require(<computed>)"}},
		{"require on the global object", "vite.config.js", "global.r = require", []string{"global[...] = ..."}},
		{"computed global key", "vite.config.js", "globalThis[atob(k)] = v", []string{"global[...] = ..."}},
		{"renamed require", "vite.config.js", "const r = require; r(x)", []string{"x = require"}},
		{"exec on a child_process module", "vite.config.js", "const cp = require('child_process'); cp.exec(atob(c))", []string{"child_process(<computed>)"}},
		{"exec on require", "vite.config.js", "require('node:child_process').exec(atob(c))", []string{"child_process(<computed>)"}},
		{"a destructured exec", "vite.config.mjs", "import { exec as run } from 'child_process'; run(atob(c))", []string{"child_process(<computed>)"}},
		{"a root name after the payload", "vite.config.js", "require(atob(m) + __dirname.slice(0, 0))", []string{"require(<computed>)"}},
		{"path.normalize of a payload", "vite.config.js", "require(path.normalize(atob(m)))", []string{"require(<computed>)"}},
		{"path.join of a payload", "vite.config.js", "require(path.join(atob(m)))", []string{"require(<computed>)"}},
		{"require.resolve of a payload", "vite.config.js", "require(require.resolve(atob(m)))", []string{"require(<computed>)"}},
		{"a payload after a long pad", "vite.config.js", strings.Repeat("\n", 2<<20) + "eval(x)", []string{"eval(...)"}},
		{"process with a computed command", "vite.config.js", "require('child_process').execSync(atob(c))", []string{"child_process(<computed>)"}},
		{"TypeScript", "vite.config.ts", "const f: Function = new Function(x as string)", []string{"Function(...)"}},
		{"one finding for each kind", "vite.config.js", "eval(a); eval(b); eval(c)", []string{"eval(...)"}},

		{"a literal command", "vite.config.js", "execSync('git rev-parse HEAD')", nil},
		{"a template with no substitution", "vite.config.js", "execSync(`git rev-parse HEAD`)", nil},
		{"a local plugin path", "webpack.config.js", "require(path.join(__dirname, 'plugins', name))", nil},
		{"a relative import", "vite.config.mjs", "await import('./' + name)", nil},
		{"a path that the path module builds", "webpack.js", "import(path.resolve(path.dirname(pkgPath), bin))", nil},
		{"a path that path.join builds on the folder", "webpack.config.js", "require(path.join(process.cwd(), 'plugins', name))", nil},
		{"a string key on the global object", "vite.config.js", "globalThis['__DEV__'] = true", nil},
		{"a regular expression exec on a binding", "vite.config.js", "const re = /a/; re.exec(s + t)", nil},
		{"a path in a variable", "cli.js", "require(cliEntry)", nil},
		{"a regular expression exec", "vite.config.js", "/a/.exec(s)", nil},
		{"eval in a string", "webpack.config.js", "module.exports = { devtool: 'eval-source-map' }", nil},
		{"a plain global setting", "vite.config.js", "globalThis.__DEV__ = true", nil},
		{"a local named require in a function", "webpack.config.js", "function load(x) { const require = x; return require('./a') }", nil},
		{"require on the global object after var require", "vite.config.js", "var require;\nglobal.r = require", []string{"global[...] = ..."}},
		{"an alias after var require", "vite.config.js", "var require; const r = require; r(atob(p))", []string{"x = require"}},
		{"eval through call", "vite.config.js", "eval.call(null, atob(p))", []string{"eval(...)"}},
		{"eval by a folded key", "vite.config.js", "globalThis['ev' + 'al'](atob(p))", []string{"eval(...)"}},
		{"exec on a module that an assignment binds", "vite.config.js", "let cp; cp = require('child_process'); cp['exec'](atob(c))", []string{"child_process(<computed>)"}},
		{"require on an alias of the global object", "vite.config.js", "const g = globalThis; g.r = require", []string{"global[...] = ..."}},
		{"a value limit that hides a module", "vite.config.js", hiddenByValueLimit, []string{"<not read>"}},
		{"a computed key on window", "App.js", "window['ga-disable-' + GA_ID] = !consent", nil},
		{"a computed key on self", "App.js", "const root = typeof self !== 'undefined' ? self : window; root[name] = plugin", nil},
		{"require through call with a plain name", "webpack.config.js", "require.call(null, 'html-webpack-plugin')", nil},
		{"require through apply with a plain name", "webpack.config.js", "require.apply(null, ['html-webpack-plugin'])", nil},
		{"require through apply with a computed name", "vite.config.js", "require.apply(null, [atob(m)])", []string{"require(<computed>)"}},
		{"require through apply with a list from elsewhere", "vite.config.js", "require.apply(null, args())", []string{"require(<computed>)"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, s := range dynamicCode(configText, tc.path, []byte(tc.data), false) {
				assert.Equal(t, IDDynamicCode, s.ID)
				got = append(got, s.Visible)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// hiddenByValueLimit binds a name to 16 modules before child_process. The
// analysis keeps 16 values for a name, so it cannot read the last one.
var hiddenByValueLimit = func() string {
	var b strings.Builder
	b.WriteString("var cp;")
	for i := range 16 {
		fmt.Fprintf(&b, "cp = require('m%d');", i)
	}
	b.WriteString("var cp = require('child_process'); cp.exec(atob(c))")
	return b.String()
}()

func TestDynamicCodeTooComplexToRead(t *testing.T) {
	s := dynamicCode(configText, "vite.config.js", []byte(strings.Repeat("a;", 400_000)), false)
	require.Len(t, s, 1)
	assert.Equal(t, "<not read>", s[0].Visible)
	assert.Equal(t, "The build config is too large or too complex for vet to read in full on line 1", s[0].Title)
}

func TestRunsAsScriptPastTheNodeLimit(t *testing.T) {
	_, parsed := runsAsScript([]byte(strings.Repeat("require(x);\n", 300_000)))
	assert.False(t, parsed, "the text check reads an asset that the parse cannot read in full")
}

func TestDynamicCodeLongCallChain(t *testing.T) {
	data := []byte("x" + strings.Repeat("()", 300_000))
	start := time.Now()
	dynamicCode(configText, "vite.config.js", data, false)
	assert.Less(t, time.Since(start), 10*time.Second)
}

func TestRunsAsScript(t *testing.T) {
	cases := []struct {
		name, data string
		want       bool
	}{
		{"a script", "require('x')", true},
		{"after an HTML-like comment", "<!-- logo -->\nrequire('x')", true},
		{"after an empty object", "{}\nrequire('x')", true},
		{"a NUL byte in a comment", "/*\x00*/require('x')", true},
		{"an SVG image", `<svg xmlns="http://www.w3.org/2000/svg"><script>require('x')</script></svg>`, false},
		{"a source map", `{"version":3,"sourcesContent":["require('x')"]}`, false},
		{"IE style sheet hacks", "* html .x { _top: expression(eval(document.body.scrollTop)); }", false},
		{"a comment with an example", "/* const x = require('y') */\n.a { color: red }", false},
		{"no call", "const x = 1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runs, parsed := runsAsScript([]byte(tc.data))
			assert.True(t, parsed)
			assert.Equal(t, tc.want, runs)
		})
	}
}

func TestDynamicCodeTitle(t *testing.T) {
	s := dynamicCode(entryText, "node_modules/npm/lib/cli.js", []byte("require('./cli/entry.js')(process)\nglobal['r']=require\n"), false)
	require.Len(t, s, 1)
	assert.Equal(t, 2, s[0].Line)
	assert.Equal(t, "The npm entry script puts require, eval or Function, or a key that it computes, on the global object on line 2", s[0].Title)
}

func FuzzDynamicCode(f *testing.F) {
	for _, s := range []string{
		"global['r']=require;(function(){var f=Function(atob('eA=='));f();})();",
		"(0, eval /* x */)('1')",
		"const { exec: run } = require('child_process'); run(atob(c))",
		"require(path.join(__dirname, x))",
		"<!-- x -->\nrequire('x')",
		"x()()()",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		dynamicCode(configText, "vite.config.js", []byte(text), false)
		runsAsScript([]byte(text))
	})
}

func TestLoadedSpecs(t *testing.T) {
	data := "const base = require('../../jest.config.base');\nimport x from './x.mjs';\nexport * from './y';\nconst z = await import('./z');\nrequire(name);\nrequire('jest-util');\n"
	assert.Equal(t, []string{"../../jest.config.base", "./z", "jest-util", "./x.mjs", "./y"}, loadedSpecs("jest.config.mjs", []byte(data)))
	setup := "module.exports = { setupFiles: ['<rootDir>/a.js', './b'], 'globalSetup': './c.js', other: './d.js' };\n"
	assert.Equal(t, []string{"./a.js", "./b", "./c.js"}, loadedSpecs("jest.config.js", []byte(setup)))
	exported := "export default { setupFiles: ['./a.js'] };\nexport * from './b';\n"
	assert.Equal(t, []string{"./a.js", "./b"}, loadedSpecs("vitest.config.mjs", []byte(exported)))
	rooted := "module.exports = { setupFiles: ['<rootDir>/setup.js'], rootDir: './src' };\n"
	assert.Equal(t, []string{"./src/setup.js"}, loadedSpecs("jest.config.js", []byte(rooted)))
	projects := "module.exports = { projects: [{ rootDir: './a', setupFiles: ['<rootDir>/setup.js'] }, { setupFiles: ['<rootDir>/setup.js'], rootDir: './b' }, { setupFiles: ['<rootDir>/c.js'] }] };\n"
	assert.Equal(t, []string{"./a/setup.js", "./b/setup.js", "./c.js"}, loadedSpecs("jest.config.js", []byte(projects)))
}

func TestRoutedFiles(t *testing.T) {
	loader := "global['r']=require;(function(){var f=Function(atob('Y29uc29sZS5sb2coMSk='));f();})();\n"
	fsys := fstest.MapFS{
		"api.js":              {Data: []byte(loader)},
		"clean.js":            {Data: []byte("module.exports = { testEnvironment: 'node' };\n")},
		"jest.config.base.js": {Data: []byte(loader)},
		"data.json":           {Data: []byte(loader)},
		"mid.js":              {Data: []byte("module.exports = require('./api');\n")},
		"src/api.js":          {Data: []byte(loader)},
		"setup.txt":           {Data: []byte(loader)},
		"style.css":           {Data: []byte(loader)},
	}
	cases := []struct {
		name, path, data string
		want             []string
	}{
		{"a config loads a loader", "apps/a/jest.config.js", "require('../../api');\nmodule.exports = {};\n", []string{"dynamic-code api.js", "dynamic-code api.js"}},
		{"an ESM config loads a loader", "vite.config.mjs", "import './api.js';\nexport default {};\n", []string{"dynamic-code api.js", "dynamic-code api.js"}},
		{"a config loads a clean file", "jest.config.js", "module.exports = require('./clean');\n", nil},
		{"a config loads a config, which gets its own check", "jest.config.js", "module.exports = require('./jest.config.base');\n", nil},
		{"a config loads a package", "jest.config.js", "module.exports = require('api');\n", nil},
		{"a config loads a file that is not JavaScript", "jest.config.js", "module.exports = require('./data.json');\n", nil},
		{"a config loads a file with another extension, which node runs as JavaScript", "jest.config.js", "require('./setup.txt');\n", []string{"dynamic-code setup.txt", "dynamic-code setup.txt"}},
		{"a config loads a style sheet", "vite.config.js", "import './style.css';\n", nil},
		{"the check does not follow a file that a routed file loads", "jest.config.js", "module.exports = require('./mid');\n", nil},
		{"a jest config names a setup file", "jest.config.js", "module.exports = { setupFiles: ['<rootDir>/api.js'], globalSetup: './clean.js' };\n", []string{"dynamic-code api.js", "dynamic-code api.js"}},
		{"the jest key of a package.json names a setup file", "package.json", `{"jest":{"setupFilesAfterEnv":["./api.js"]}}`, []string{"dynamic-code api.js", "dynamic-code api.js"}},
		{"the jest key of a package.json names a setup file under its root", "package.json", `{"jest":{"rootDir":"src","setupFiles":["<rootDir>/api.js"]}}`, []string{"dynamic-code src/api.js", "dynamic-code src/api.js"}},
		{"a hook runs another script", "package.json", `{"scripts":{"pretest":"npm run setup","setup":"node api.js"}}`, []string{"script-hook-added package.json", "dynamic-code api.js", "dynamic-code api.js"}},
		{"a hook runs a loader", "package.json", `{"scripts":{"pretest":"node api.js"}}`, []string{"script-hook-added package.json", "dynamic-code api.js", "dynamic-code api.js"}},
		{"a pre script of another script runs a loader", "package.json", `{"scripts":{"prebuild":"node api","build":"tsc"}}`, []string{"script-hook-added package.json", "dynamic-code api.js", "dynamic-code api.js"}},
		{"a hook runs a clean file", "package.json", `{"scripts":{"postinstall":"node clean.js"}}`, []string{"script-hook-added package.json"}},
		{"test runs a loader with no hook", "package.json", `{"scripts":{"test":"node api.js && jest"}}`, []string{"dynamic-code api.js", "dynamic-code api.js"}},
		{"a build script is not read", "package.json", `{"scripts":{"build":"node api.js"}}`, nil},
		{"a hook runs a file that is not there", "package.json", `{"scripts":{"prepare":"node gone.js"}}`, nil},
		{"two hooks run one file", "package.json", `{"scripts":{"pretest":"node api.js","posttest":"node api.js"}}`, []string{"script-hook-added package.json", "script-hook-added package.json", "dynamic-code api.js", "dynamic-code api.js"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := Classify(tc.path)
			require.True(t, ok)
			var got []string
			for _, s := range Analyze(fsys, c, tc.path, []byte(tc.data)) {
				p := s.Path
				if p == "" {
					p = tc.path
				}
				got = append(got, s.ID+" "+p)
			}
			assert.Equal(t, tc.want, got)
		})
	}

	s := Analyze(fsys, Config, "apps/a/jest.config.js", []byte("require('../../api');\n"))
	require.Len(t, s, 2)
	assert.Equal(t, "api.js, which jest.config.js loads, puts require, eval or Function, or a key that it computes, on the global object on line 1", s[0].Title)
	h := Analyze(fsys, Hooks, "package.json", []byte("{\n  \"scripts\": {\n    \"pretest\": \"node api.js\"\n  }\n}\n"))
	require.Len(t, h, 3)
	assert.Equal(t, 3, h[0].Line)
	assert.Equal(t, `"pretest": "node api.js"`, h[0].Visible)
	assert.Equal(t, "The pretest script runs api.js, a file of the project. npm runs the script on its own, and the user does not see it", h[0].Title)
}

func TestRoutedFilesHaveALimit(t *testing.T) {
	loader := "eval(x);\n"
	fsys := fstest.MapFS{}
	var config strings.Builder
	for i := range maxRouted + 4 {
		name := fmt.Sprintf("f%02d.js", i)
		fsys[name] = &fstest.MapFile{Data: []byte(loader)}
		config.WriteString("require('./" + name + "');\n")
	}
	paths := map[string]bool{}
	for _, s := range Analyze(fsys, Config, "jest.config.js", []byte(config.String())) {
		paths[s.Path] = true
	}
	assert.Len(t, paths, maxRouted)

	var skipped strings.Builder
	for i := range maxRouted + 4 {
		name := fmt.Sprintf("d%02d.json", i)
		fsys[name] = &fstest.MapFile{Data: []byte("{}")}
		skipped.WriteString("require('./" + name + "');\n")
	}
	skipped.WriteString("require('./f00.js');\n")
	got := Analyze(fsys, Config, "jest.config.js", []byte(skipped.String()))
	require.NotEmpty(t, got, "a file that vet does not read does not count against the limit")
	assert.Equal(t, "f00.js", got[0].Path)

	var unread strings.Builder
	for i := range maxRouted + 4 {
		name := fmt.Sprintf("u%02d.js", i)
		fsys[name] = &fstest.MapFile{Data: []byte("1")}
		unread.WriteString("require('./" + name + "');\n")
	}
	unread.WriteString("require('./f00.js');\n")
	got = Analyze(failOpen{fsys}, Config, "jest.config.js", []byte(unread.String()))
	require.NotEmpty(t, got, "a file that vet cannot open does not count against the limit")
	assert.Equal(t, "f00.js", got[0].Path)
}

// failOpen fails to open each file whose name starts with u, as a file
// that the user cannot read does.
type failOpen struct{ fstest.MapFS }

func (f failOpen) Open(name string) (fs.File, error) {
	if strings.HasPrefix(name, "u") {
		return nil, fs.ErrPermission
	}
	return f.MapFS.Open(name)
}

func TestRoutedFilesKeepOnlyTheKindsOfALoader(t *testing.T) {
	cases := []struct {
		name, data string
		want       []string
	}{
		{"eval", "eval(x)", []string{"eval(...)"}},
		{"Function", "new Function(x)()", []string{"Function(...)"}},
		{"require on the global object", "global.r = require", []string{"global[...] = ..."}},
		{"a process with a computed command", "require('child_process').execSync(`npm run ${x}`)", nil},
		{"a computed require", "require(path.join(dir, name))", nil},
		{"a file too large to read", strings.Repeat("a;", 400_000), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, s := range dynamicCode("scripts/build.js", "scripts/build.js", []byte(tc.data), true) {
				got = append(got, s.Visible)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}
