package controls

import (
	"fmt"
	"strings"
)

// The markers of the generated blocks of docs/controls.md.
const (
	TableStart     = "<!-- controls:table:start -->"
	TableEnd       = "<!-- controls:table:end -->"
	ReferenceStart = "<!-- controls:reference:start -->"
	ReferenceEnd   = "<!-- controls:reference:end -->"
)

// Table returns the markdown table of the controls. Each id links to its
// section of the reference.
func Table(list []Info) string {
	var b strings.Builder
	b.WriteString("| Control | Family | Default severity | Finds |\n| --- | --- | --- | --- |\n")
	for _, c := range list {
		fmt.Fprintf(&b, "| [`%s`](#%s) | %s | %s | %s |\n", c.ID, c.ID, c.Family, c.Severity, c.Title)
	}
	return b.String()
}

// Reference returns one section for each control. The heading is the
// control id, so a link to controls.md#<id> opens it.
func Reference(list []Info) string {
	var b strings.Builder
	for i, c := range list {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "### %s\n\n**%s.** Family `%s`. Default severity %s. Plugin `%s`.", c.ID, c.Title, c.Family, c.Severity, c.Plugin)
		if c.Attack {
			b.WriteString(" The attacks gate fails on it.")
		}
		fmt.Fprintf(&b, "\n\n%s\n", c.Description)
	}
	return b.String()
}

// RenderDoc replaces the generated blocks of a controls doc.
func RenderDoc(doc string, list []Info) (string, error) {
	doc, err := replaceBlock(doc, TableStart, TableEnd, Table(list))
	if err != nil {
		return "", err
	}
	return replaceBlock(doc, ReferenceStart, ReferenceEnd, Reference(list))
}

func replaceBlock(doc, start, end, body string) (string, error) {
	i, j := strings.Index(doc, start), strings.Index(doc, end)
	if i < 0 || j < i {
		return "", fmt.Errorf("the doc has no %s block", start)
	}
	return doc[:i+len(start)] + "\n\n" + body + "\n" + doc[j:], nil
}
