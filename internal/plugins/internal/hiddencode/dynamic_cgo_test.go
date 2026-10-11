//go:build cgo

package hiddencode

import (
	"strings"
	"testing"

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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, s := range dynamicCode(Config, tc.path, []byte(tc.data)) {
				assert.Equal(t, IDDynamicCode, s.ID)
				got = append(got, s.Visible)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDynamicCodeTitle(t *testing.T) {
	s := dynamicCode(Entry, "node_modules/npm/lib/cli.js", []byte("require('./cli/entry.js')(process)\nglobal['r']=require\n"))
	require.Len(t, s, 1)
	assert.Equal(t, 2, s[0].Line)
	assert.Equal(t, "The npm entry script puts require, eval or Function, or a key that it computes, on the global object on line 2", s[0].Title)
}
