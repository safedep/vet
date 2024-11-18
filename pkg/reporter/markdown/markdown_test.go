package markdown

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarkdownBuilder(t *testing.T) {
	cases := []struct {
		name     string
		opsFn    func(builder *MarkdownBuilder)
		contains string
	}{
		{
			"Has simple text",
			func(builder *MarkdownBuilder) {
				builder.AddParagraph("AAAABBBB")
			},
			"AAAABBBB",
		},
		{
			"Has headings h1",
			func(builder *MarkdownBuilder) {
				builder.AddHeader(1, "AAAABBBB")
			},
			"# AAAABBBB",
		},
		{
			"Has headings h2",
			func(builder *MarkdownBuilder) {
				builder.AddHeader(2, "AAAABBBB")
			},
			"## AAAABBBB",
		},
		{
			"Has bullet points",
			func(builder *MarkdownBuilder) {
				builder.AddBulletPoint("AAAA")
				builder.AddBulletPoint("BBBB")
			},
			"- AAAA\n- BBBB",
		},
		{
			"Has collapsible section",
			func(builder *MarkdownBuilder) {
				section := builder.StartCollapsibleSection("Title")
				section.Builder().AddParagraph("AAAABBBB")
				builder.AddCollapsibleSection(section)
			},
			"<details>\n<summary>Title</summary>\n\nAAAABBBB\n\n</details>",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			builder := NewMarkdownBuilder()
			assert.NotNil(t, builder)

			test.opsFn(builder)

			assert.Contains(t, builder.Build(), test.contains)
		})
	}
}
