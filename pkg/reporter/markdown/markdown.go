package markdown

import (
	"bytes"
	"fmt"
	"strings"
)

type MarkdownBuilder struct {
	content bytes.Buffer
}

type MarkdownCollapsibleSection struct {
	title   string
	builder *MarkdownBuilder

	// Only github for now
	flavor string
}

func (s *MarkdownCollapsibleSection) Builder() *MarkdownBuilder {
	return s.builder
}

func NewMarkdownBuilder() *MarkdownBuilder {
	return &MarkdownBuilder{}
}

// AddHeader adds a header to the markdown document.
func (mb *MarkdownBuilder) AddHeader(level int, text string) {
	mb.content.WriteString(fmt.Sprintf("%s %s\n", strings.Repeat("#", level), text))
}

// AddParagraph adds a paragraph to the markdown document.
func (mb *MarkdownBuilder) AddParagraph(text string) {
	mb.content.WriteString(fmt.Sprintf("%s\n\n", text))
}

// AddBulletPoint adds a bullet point to the markdown document.
func (mb *MarkdownBuilder) AddBulletPoint(text string) {
	mb.content.WriteString(fmt.Sprintf("- %s\n", text))
}

// AddNumberedPoint adds a numbered point to the markdown document.
func (mb *MarkdownBuilder) AddNumberedPoint(number int, text string) {
	mb.content.WriteString(fmt.Sprintf("%d. %s\n", number, text))
}

// AddCodeSnippet adds a code snippet to the markdown document.
func (mb *MarkdownBuilder) AddCodeSnippet(code, language string) {
	mb.content.WriteString("```" + language + "\n")
	mb.content.WriteString(code + "\n")
	mb.content.WriteString("```\n")
}

func (mb *MarkdownBuilder) AddRaw(content string) {
	mb.content.WriteString("\n" + content + "\n")
}

func (mb *MarkdownBuilder) AddQuote(text string) {
	mb.content.WriteString("> " + text + "\n")
}

// StartCollapsibleSection starts a collapsible section in the markdown document.
func (mb *MarkdownBuilder) StartCollapsibleSection(title string) *MarkdownCollapsibleSection {
	return &MarkdownCollapsibleSection{
		title:   title,
		flavor:  "github",
		builder: NewMarkdownBuilder(),
	}
}

// AddCollapsibleSection adds a collapsible section to the markdown document.
func (mb *MarkdownBuilder) AddCollapsibleSection(section *MarkdownCollapsibleSection) {
	if section.flavor != "github" {
		return
	}

	mb.content.WriteString(fmt.Sprintf("<details>\n<summary>%s</summary>\n\n", section.title))
	mb.content.WriteString(section.builder.Build())
	mb.content.WriteString("</details>\n\n")
}

func (mb *MarkdownBuilder) Build() string {
	return mb.content.String()
}
