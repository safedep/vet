package markdown

import (
	"bytes"
	"fmt"
	"regexp"
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

var (
	headerBulletRegex   = regexp.MustCompile(`(?m)^(#{1,6}\s+|[-*]\s{1,}|\d+\.\s+|>\s+)`)
	inlineCodeRegex     = regexp.MustCompile("`{1,3}([^`]*)`{1,3}")
	horizontalRuleRegex = regexp.MustCompile(`(?m)^\s*(-{3,}|\*{3,}|\_{3,})\s*$`)
	boldItalicRegex     = regexp.MustCompile(`(?:\*\*\*|___)(.*?)(?:\*\*\*|___)`)
	boldRegex           = regexp.MustCompile(`(?:\*\*|__)(.*?)(?:\*\*|__)`)
	italicRegex         = regexp.MustCompile(`(?:\*|_)(.*?)(?:\*|_)`)
	strikethroughRegex  = regexp.MustCompile(`~~([^~]+)~~`)
	inlineLinkRegex     = regexp.MustCompile(`\[([^\]]+)\]\((\S+?)\)`)
	imageRegex          = regexp.MustCompile(`!\[([^\]]*)\]\((\S+?)\)`)
	extraSpacesRegex    = regexp.MustCompile(`\s+`)
)

func (mb *MarkdownBuilder) BuildPlainText() string {
	content := mb.content.String()
	content = headerBulletRegex.ReplaceAllString(content, "")
	content = inlineCodeRegex.ReplaceAllString(content, "$1")
	content = horizontalRuleRegex.ReplaceAllString(content, "")
	content = boldItalicRegex.ReplaceAllString(content, "$1")
	content = boldRegex.ReplaceAllString(content, "$1")
	content = italicRegex.ReplaceAllString(content, "$1")
	content = strikethroughRegex.ReplaceAllString(content, "$1")
	content = imageRegex.ReplaceAllString(content, "$1")
	content = inlineLinkRegex.ReplaceAllString(content, "$1")
	content = extraSpacesRegex.ReplaceAllString(content, " ")

	return strings.Trim(content, " \n")
}
