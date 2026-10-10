package hiddencode

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ids(signals []Signal) []string {
	var out []string
	for _, s := range signals {
		out = append(out, s.ID)
	}
	return out
}

func TestPadded(t *testing.T) {
	payload := "global['_V']='8-st14';console.log(1)"
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
	s := Analyze(Config, "postcss.config.mjs", []byte("export default config;"+strings.Repeat(" ", 280)+"eval(x)"))
	require.Len(t, s, 1)
	assert.Equal(t, "export default config;", s[0].Visible)
	assert.Equal(t, "Code continues on line 1 after 280 spaces, with 7 bytes off screen", s[0].Title)
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
		{"payload with no decoder", "src/index.js", "const x = `" + payload + "`;\n", []string{IDInvisibleUnicode}},
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

func TestInvisibleSnippetHasNoPayload(t *testing.T) {
	s := Analyze(Source, "src/index.js", []byte("const x = `"+selectors("payload")+"`;\n"))
	require.Len(t, s, 1)
	assert.Equal(t, "const x = ``;", s[0].Visible)
}
