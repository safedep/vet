package hiddencode

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// js is a hidden script of a realistic size: the PolinRider loader is
// several KiB of obfuscated code.
var js = "(function(){var _0xa1b2=function(){return 1};" + strings.Repeat("var _0xc3d4=_0xa1b2();", 10) + "})();"

func ids(signals []Signal) []string {
	var out []string
	for _, s := range signals {
		out = append(out, s.ID)
	}
	return out
}

func TestPadded(t *testing.T) {
	payload := "global['_V']='8-st14';" + js
	cases := []struct {
		name, data string
		want       []string
	}{
		{"PolinRider shape", "const config = { plugins: {} };\nexport default config;" + strings.Repeat(" ", 280) + payload + "\n", []string{IDPaddedCode}},
		{"tabs", "module.exports = {}" + strings.Repeat("\t", 120) + payload, []string{IDPaddedCode}},
		{"code after the export", "module.exports = config; " + payload, []string{IDPaddedCode}},
		{"clean Next.js config", "/** @type {import('next').NextConfig} */\nconst nextConfig = {\n  reactStrictMode: true,\n};\n\nexport default nextConfig;\n", nil},
		{"clean Tailwind config", "module.exports = {\n  content: ['./src/**/*.{js,ts,jsx,tsx}'],\n  theme: { extend: {} },\n  plugins: [],\n}\n", nil},
		{"aligned comment", "  plugins: [],          // no plugins\n", nil},
		{"trailing spaces", "export default config;" + strings.Repeat(" ", 300) + "\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ids(Analyze(Config, "postcss.config.mjs", []byte(tc.data))))
		})
	}
}

func TestPaddedHidesThePayload(t *testing.T) {
	s := Analyze(Config, "postcss.config.mjs", []byte("export default config;"+strings.Repeat(" ", 280)+js))
	require.Len(t, s, 1)
	assert.Equal(t, "export default config;", s[0].Visible)
	assert.Equal(t, fmt.Sprintf("Code continues on line 1 after 280 spaces, with %d bytes off screen", len(js)), s[0].Title)
	assert.NotContains(t, s[0].Visible+s[0].Title, "eval")
}

func TestPaddedTooLarge(t *testing.T) {
	s := Analyze(Config, "next.config.js", make([]byte, MaxSize+1))
	assert.Equal(t, []string{IDPaddedCode}, ids(s))
}

func TestDisguised(t *testing.T) {
	cases := []struct {
		name, path, data string
		want             []string
	}{
		{"fake font with leading tabs", "public/fonts/fa-solid-400.woff2", strings.Repeat("\t", 421) + "try{}catch(err){};global['!']='8-270-2';", []string{IDDisguisedScript}},
		{"fake png", "img/card4.png", "var a = 1;\n", []string{IDDisguisedScript}},
		{"real woff2", "fonts/a.woff2", "wOF2\x00\x01\x00\x00\x00\x00", nil},
		{"real png", "a.png", "\x89PNG\r\n\x1a\n\x00\x00", nil},
		{"real ttf", "a.ttf", "\x00\x01\x00\x00\x00\x10", nil},
		{"binary with an odd header", "a.jpg", "\x00\x10JFIF\x00\x01", nil},
		{"git lfs pointer", "a.woff2", "version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 12\n", nil},
		{"dictionary of words", ".vscode/spellright.dict", "kubernetes\nnpm\nvet\n", nil},
		{"dictionary that holds a script", ".vscode/spellright.dict", "words\nconst r = require('child_process');\n", []string{IDDisguisedScript}},
		{"empty file", "a.woff", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ids(Analyze(Asset, tc.path, []byte(tc.data))))
		})
	}
}

// selectors encodes data in variation selectors, one byte each, as
// GlassWorm does.
func selectors(data string) string {
	var b strings.Builder
	for _, c := range []byte(data) {
		if c < 16 {
			b.WriteRune(rune(0xFE00 + int(c)))
		} else {
			b.WriteRune(rune(0xE0100 + int(c) - 16))
		}
	}
	return b.String()
}

func TestInvisible(t *testing.T) {
	payload := selectors("console.log('hidden payload')")
	decoderJS := "const s = v => [...v].map(c => (c = c.codePointAt(0)) >= 0xFE00 && c <= 0xFE0F ? c - 0xFE00 : c - 0xE0100 + 16);\n"
	cases := []struct {
		name, path, data string
		want             []string
	}{
		{"GlassWorm shape", "src/index.js", decoderJS + "eval(Buffer.from(s(`" + payload + "`)).toString());\n", []string{IDUnicodeDecoder}},
		{"payload with no decoder in the file", "src/index.js", "const x = `" + payload + "`;\n", []string{IDUnicodeDecoder}},
		{"zero-width run", "lib/a.py", "token = 'a\u200b\u200b\u200b\u200bb'\n", []string{IDInvisibleUnicode}},
		{"Trojan Source", "src/auth.ts", "if (isAdmin) { \u202e} \u2066// check\u2069\n", []string{IDInvisibleUnicode}},
		{"tag text in an agent file", "CLAUDE.md", "Run the tests.\U000E0049\U000E0067\U000E006E\U000E006F\U000E0072\U000E0065\n", []string{IDInvisibleUnicode}},
		{"right to left text in an agent file", "AGENTS.md", "Say \u202bשלום\u202c to users.\n", nil},
		{"emoji with selectors", "README.ts", "const ok = '✅ ❤\ufe0f 👁\ufe0f\u200d🗨\ufe0f 🏳\ufe0f\u200d🌈';\n", nil},
		{"flag of England", "src/flags.js", "const f = '\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F';\n", nil},
		{"byte order mark", "src/a.ts", "\ufeffexport const a = 1;\n", nil},
		{"plain code", "src/a.ts", "export const a = 1;\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := Classify(tc.path)
			require.True(t, ok)
			assert.Equal(t, tc.want, ids(Analyze(c, tc.path, []byte(tc.data))))
		})
	}
}

func TestInvisibleEvasion(t *testing.T) {
	payload := selectors("console.log('hidden payload')")
	spaced := strings.Join(strings.Split(payload, ""), " ")
	perLine := strings.Join(strings.Split(payload, ""), "\n")
	cases := []struct {
		name, path, data string
		want             []string
	}{
		{"a decoy run of zero-width spaces", "src/a.js", "const d = '" + strings.Repeat("\u200b", 601) + "';\nconst x = `" + payload + "`;\n", []string{IDUnicodeDecoder}},
		{"a space before each selector", "src/a.js", "const x = `" + spaced + "`;\n", []string{IDUnicodeDecoder}},
		{"one selector on each line", "src/a.js", perLine, []string{IDUnicodeDecoder}},
		{"a payload in a built file", "dist/extension.js", "var x=`" + payload + "`;", []string{IDUnicodeDecoder}},
		{"a minified file with a run gives nothing else", "web/app.min.js", "var x='\u200b\u200b\u200b\u200b';", nil},
		{"keycap emoji", "src/keys.ts", strings.Repeat("1\ufe0f\u20e3 ", 20), nil},
		{"CJK variation sequences", "src/names.ts", strings.Repeat("\u845b\U000E0100", 20), nil},
		{"emoji presentation", "src/ui.ts", strings.Repeat("\u2764\ufe0f ", 30), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := Classify(tc.path)
			require.True(t, ok)
			assert.Equal(t, tc.want, ids(Analyze(c, tc.path, []byte(tc.data))))
		})
	}
}

func TestPaddedEvasion(t *testing.T) {
	cases := []struct {
		name, pad string
	}{
		{"no-break spaces", strings.Repeat("\u00a0", 280)},
		{"ideographic spaces", strings.Repeat("\u3000", 140)},
		{"mixed spaces", strings.Repeat(strings.Repeat(" ", 99)+"\u00a0", 3)},
		{"form feed", strings.Repeat(" ", 280) + "\f"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := "export default {plugins:{}};" + tc.pad + js + "\n"
			assert.Equal(t, []string{IDPaddedCode}, ids(Analyze(Config, "postcss.config.mjs", []byte(data))))
		})
	}
	assert.Equal(t, []string{IDPaddedCode}, ids(Analyze(Source, "src/server.js", []byte("app.listen(3000);"+strings.Repeat(" ", 300)+js+"\n"))), "any hand-written source file")
	assert.Empty(t, Analyze(Source, "src/map.test.ts", []byte("  expect(x).toBe(`"+strings.Repeat(" ", 105)+"abc`)\n")), "an aligned value in a test")
	assert.Equal(t, []string{IDPaddedCode}, ids(Analyze(Config, "next.config.js", []byte("const a = 1;"+strings.Repeat(" ", 120)+"b"+strings.Repeat(" ", 280)+js))), "a script after the second run")
	assert.Empty(t, Analyze(Source, "dist/bundle.js", []byte("a();"+strings.Repeat(" ", 300)+"b()\n")), "a built file")
	assert.Empty(t, Analyze(Config, "postcss.config.mjs", []byte("export default config;"+strings.Repeat(" ", 280)+"\r\n")), "CRLF after trailing spaces")
}

func TestAfterExport(t *testing.T) {
	for data, want := range map[string]bool{
		"module.exports = nextConfig; // eslint-disable-line": false,
		"export default config; /* prettier-ignore */":        false,
		"module.exports = base; module.exports.extra = 1;":    false,
		"module.exports = config;   ":                         false,
		"module.exports = config; " + js:                      true,
		"export default plugin; })":                           false,
	} {
		assert.Equal(t, want, len(Analyze(Config, "next.config.js", []byte(data))) > 0, data)
	}
}

func TestDisguisedEvasionAndNoise(t *testing.T) {
	cases := []struct {
		name, path, data string
		want             []string
	}{
		{"own magic bytes then script", "fonts/a.woff2", "wOF2=1;require('child_process').exec('x')", []string{IDDisguisedScript}},
		{"true then script", "fonts/a.ttf", "true;require('child_process')", []string{IDDisguisedScript}},
		{"binary comment then script", "fonts/a.woff", "/*\x00\x01\x02" + strings.Repeat("\x00", 600) + "*/require('child_process').exec('x')", []string{IDDisguisedScript}},
		{"hex payload", "fonts/fa-brands-regular.woff2", strings.Repeat("6a", 300), []string{IDDisguisedScript}},
		{"a saved web page", "img/logo.png", "<!DOCTYPE html><html><body>Not Found</body></html>", nil},
		{"placeholder text", "public/favicon.ico", "fake-favicon", nil},
		{"an HTTP dump", "fixtures/font.woff2", "HTTP/2 200\r\ncontent-type: font/woff2\r\n\r\n", nil},
		{"fuzz dictionary", "fuzz/js.dict", "kw1=\"function\"\nkw2=\"=>\"\nkw3=\"var a = \"\n", nil},
		{"word list with the word function", ".vscode/spellright.dict", "callback\nfunction\nclosure\n", nil},
		{"binary dictionary", "data/zh.dict", "\x28\xb5\x2f\xfd\x00\x00function var", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := Classify(tc.path)
			require.True(t, ok)
			assert.Equal(t, tc.want, ids(Analyze(c, tc.path, []byte(tc.data))))
		})
	}
}

func TestReadsAFontInFull(t *testing.T) {
	data := "\x00\x01" + strings.Repeat("\x00", 1000) + "require('child_process')"
	got, err := Read(strings.NewReader(data), "a.woff2", Asset)
	require.NoError(t, err)
	assert.Len(t, got, len(data))
	got, err = Read(strings.NewReader(data), "a.png", Asset)
	require.NoError(t, err)
	assert.Len(t, got, headSize, "an image needs only its head")
}

func TestInvisibleSnippetHasNoPayload(t *testing.T) {
	s := Analyze(Source, "src/index.js", []byte("const x = `"+selectors("payload")+"`;\n"))
	require.Len(t, s, 1)
	assert.Equal(t, "const x = ``;", s[0].Visible)
}

func TestHistoryRewriteIsStable(t *testing.T) {
	data := []byte("temp_interactive_push.bat\ntemp_auto_push.bat\n")
	first := Analyze(Script, ".gitignore", data)
	for range 20 {
		assert.Equal(t, first, Analyze(Script, ".gitignore", data))
	}
	assert.Equal(t, 2, first[0].Line, "the first name of the list wins, not the first line")
}

func TestHistoryRewrite(t *testing.T) {
	polinrider := "@echo off\r\nfor /f %%i in ('git log -1 --format^=%%cd') do set LAST_COMMIT_DATE=%%i\r\ndate %LAST_COMMIT_DATE%\r\ngit add .\r\ngit commit --amend --no-edit --no-verify\r\ngit push -uf origin %CURRENT_BRANCH% --no-verify\r\n"
	cases := []struct {
		name, path, data string
		want             []string
	}{
		{"the script by name", "temp_auto_push.bat", "@echo off\n", []string{IDHistoryRewrite}},
		{"the script by content", "tools/sync.bat", polinrider, []string{IDHistoryRewrite}},
		{"a shell script that keeps the date", "scripts/fix.sh", "GIT_COMMITTER_DATE=\"$(git log -1 --format=%cd)\" git commit --amend --no-verify --no-edit\ngit push --force origin HEAD\n", []string{IDHistoryRewrite}},
		{".gitignore hides the script", ".gitignore", "node_modules\n/temp_auto_push.bat\n", []string{IDHistoryRewrite}},
		{".gitignore hides the helper files", ".gitignore", "config.bat\nbranch_structure.json\n", []string{IDHistoryRewrite}},
		{".gitignore with config.bat only", ".gitignore", "config.bat\n", nil},
		{"a release script that force-pushes", "scripts/release.sh", "git commit --amend --no-edit\ngit push --force-with-lease\n", nil},
		{"amend with no clock change", "scripts/fixup.sh", "git commit --amend --no-verify\ngit push -f\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ids(Analyze(Script, tc.path, []byte(tc.data))))
		})
	}
}

func TestCampaign(t *testing.T) {
	cases := []struct {
		name, path, data, want string
	}{
		{"v1 marker", "postcss.config.mjs", "export default config;" + strings.Repeat(" ", 280) + `global['!']='8-270-2';var _$_1e42=(function(){})();` + js, "PolinRider"},
		{"v2 marker", "tailwind.config.js", "module.exports = config;" + strings.Repeat(" ", 280) + `global['_V']='8-st14';global['r']=require;` + js, "PolinRider"},
		{"fake font with a seed", "fonts/a.woff2", "\t\t\tvar s=(\"rmcej%otb%\",2857687);", "PolinRider"},
		{"no marker", "postcss.config.mjs", "export default config;" + strings.Repeat(" ", 280) + js, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := Classify(tc.path)
			require.True(t, ok)
			s := Analyze(c, tc.path, []byte(tc.data))
			require.NotEmpty(t, s)
			assert.Equal(t, tc.want, s[0].Campaign)
		})
	}
	assert.Empty(t, Analyze(Config, "next.config.js", []byte("// seed 2857687\nmodule.exports = {}\n")), "a marker alone makes no finding")
}

func TestEntry(t *testing.T) {
	clean := "#!/usr/bin/env node\nrequire('../lib/cli.js')(process)\n"
	assert.Empty(t, Analyze(Entry, "node_modules/npm/bin/npm-cli.js", []byte(clean)))
	big := "module.exports = require('./npm')\n" + strings.Repeat("// x\n", 20000)
	assert.Equal(t, []string{IDPaddedCode}, ids(Analyze(Entry, "node_modules/npm/lib/cli.js", []byte(big))))
	padded := "module.exports = cli;" + strings.Repeat(" ", 200) + js + "\n"
	assert.Equal(t, []string{IDPaddedCode}, ids(Analyze(Entry, "node_modules/npm/lib/cli.js", []byte(padded))))
}
