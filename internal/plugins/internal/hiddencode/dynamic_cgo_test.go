//go:build cgo

package hiddencode

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
		{"computed global key", "vite.config.js", "globalThis['_V'] = '8-st14'", []string{"global[...] = ..."}},
		{"process with a computed command", "vite.config.js", "require('child_process').execSync(atob(c))", []string{"child_process(<computed>)"}},
		{"TypeScript", "vite.config.ts", "const f: Function = new Function(x as string)", []string{"Function(...)"}},
		{"one finding for each kind", "vite.config.js", "eval(a); eval(b); eval(c)", []string{"eval(...)"}},

		{"a literal command", "vite.config.js", "execSync('git rev-parse HEAD')", nil},
		{"a template with no substitution", "vite.config.js", "execSync(`git rev-parse HEAD`)", nil},
		{"a local plugin path", "webpack.config.js", "require(path.join(__dirname, 'plugins', name))", nil},
		{"a relative import", "vite.config.mjs", "await import('./' + name)", nil},
		{"a path that the path module builds", "webpack.js", "import(path.resolve(path.dirname(pkgPath), bin))", nil},
		{"a path from require.resolve", "webpack.js", "require(require.resolve(name + '/package.json'))", nil},
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
	if assert.Len(t, s, 1) {
		assert.Equal(t, 2, s[0].Line)
		assert.Equal(t, "The npm entry script puts a loader or a computed key on the global object on line 2", s[0].Title)
	}
}
