package markdown

import (
	"bytes"
	"fmt"
	"strings"
)

type MarkdownBuilder struct {
	content bytes.Buffer
}

func NewMarkdownBuilder() *MarkdownBuilder {
	return &MarkdownBuilder{}
}

func (mb *MarkdownBuilder) AddHeader(level int, text string) {
	mb.content.WriteString(fmt.Sprintf("%s %s\n", strings.Repeat("#", level), text))
}

func (mb *MarkdownBuilder) AddParagraph(text string) {
	mb.content.WriteString(fmt.Sprintf("%s\n\n", text))
}

func (mb *MarkdownBuilder) AddBulletPoint(text string) {
	mb.content.WriteString(fmt.Sprintf("- %s\n", text))
}

func (mb *MarkdownBuilder) AddNumberedPoint(number int, text string) {
	mb.content.WriteString(fmt.Sprintf("%d. %s\n", number, text))
}

func (mb *MarkdownBuilder) AddCodeSnippet(code, language string) {
	mb.content.WriteString("```" + language + "\n")
	mb.content.WriteString(code + "\n")
	mb.content.WriteString("```\n")
}

func (mb *MarkdownBuilder) Build() string {
	return mb.content.String()
}
