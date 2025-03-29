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

func TestMarkdownBuildPlainText(t *testing.T) {
	markdownText := "# Heading 1\n## Heading 2\n### Heading 3\n#### Heading 4\n" +
		"##### Heading 5\n###### Heading 6\n- Bullet list item 1  \n* Bullet list item 2\n" +
		"- Another >bullet\n1. Numbered list - item 1  \n2. Numbered list *item 2\n" +
		"> Blockquote text  \n---\n___\n**Bold text1**\n__Bold text2__  \n*Italic text1*\n" +
		"_Italic text2_ \n***Bold and Italic text*** \n___Bold and Italic text___\n" +
		"~~Strikethrough text~~ \n Line #has `Inline code` betwee # n\n" +
		"Line has ``Inline code with backticks`` betwee_n \n ```Inline code in triple backticks```\n" +
		"```\nmultiline code\n```\n```python\nprint('Hello, Markdown!')\n```\n" +
		"[Link text](https://example.com)\n![Image alt-text](https://example.com/image.jpg)\n" +
		"Extra      spaces    in      line. \n*This should be ##italic* and **this should # be #bold**.\n" +
		"~~This is crossed out~~ and `this is inline code`.\nEmoji: 🎉 🚀"

	expectedPlainText := "Heading 1 Heading 2 Heading 3 Heading 4 Heading 5 Heading 6 Bullet list item 1 Bullet list item 2 Another >bullet Numbered list - item 1 Numbered list *item 2 Blockquote text Bold text1 Bold text2 Italic text1 Italic text2 Bold and Italic text Bold and Italic text Strikethrough text Line #has Inline code betwee # n Line has Inline code with backticks betwee_n Inline code in triple backticks multiline code python print('Hello, Markdown!') Link text Image alt-text Extra spaces in line. This should be ##italic and this should # be #bold. This is crossed out and this is inline code. Emoji: 🎉 🚀"

	builder := NewMarkdownBuilder()
	assert.NotNil(t, builder)

	builder.AddRaw(markdownText)
	plainText := builder.BuildPlainText()
	assert.Equal(t, expectedPlainText, plainText)
}
