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
