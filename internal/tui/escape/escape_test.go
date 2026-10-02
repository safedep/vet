package escape

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEscape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		line string
		text string
	}{
		{name: "plain text", in: "pkg:npm/left-pad@1.3.0", line: "pkg:npm/left-pad@1.3.0", text: "pkg:npm/left-pad@1.3.0"},
		{name: "unicode", in: "naïve ✓ 日本", line: "naïve ✓ 日本", text: "naïve ✓ 日本"},
		{name: "line breaks", in: "a\nb\r\tc", line: `a\nb\r\tc`, text: "a\nb\\r\\tc"},
		{name: "ansi sequence", in: "evil\x1b[2J\x1b]0;title\x07", line: `evil\x1b[2J\x1b]0;title\x07`, text: `evil\x1b[2J\x1b]0;title\x07`},
		{name: "c1 control", in: "a\u009bb", line: `a\u009bb`, text: `a\u009bb`},
		{name: "bidi override", in: "admin‮⁦txt", line: `admin‮⁦txt`, text: `admin‮⁦txt`},
		{name: "delete", in: "a\x7fb", line: `a\x7fb`, text: `a\x7fb`},
		{name: "invalid utf-8", in: "a\xffb", line: "a�b", text: "a�b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.line, Line(tc.in))
			assert.Equal(t, tc.text, Text(tc.in))
		})
	}
}
