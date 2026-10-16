package controls

import (
	"fmt"
	"strings"

	"github.com/safedep/vet/v2/internal/technique"
)

// The markers of the generated blocks of docs/controls.md.
const (
	TableStart     = "<!-- controls:table:start -->"
	TableEnd       = "<!-- controls:table:end -->"
	ReferenceStart = "<!-- controls:reference:start -->"
	ReferenceEnd   = "<!-- controls:reference:end -->"
	TechniqueStart = "<!-- controls:techniques:start -->"
	TechniqueEnd   = "<!-- controls:techniques:end -->"
	// AttacksStart and AttacksEnd mark the list of the attack controls in
	// docs/policy.md.
	AttacksStart = "<!-- controls:attacks:start -->"
	AttacksEnd   = "<!-- controls:attacks:end -->"
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
			fmt.Fprintf(&b, " Technique [`%s`](#attack-techniques). The attacks gate fails on it.", c.Technique)
		}
		fmt.Fprintf(&b, "\n\n%s\n", c.Description)
	}
	return b.String()
}

// Techniques returns the markdown table of the attack techniques of the
// registry, with the controls that name each one.
func Techniques(list []Info) string {
	var b strings.Builder
	b.WriteString("| Technique | MITRE ATT&CK | Controls | Evasion corpus |\n| --- | --- | --- | --- |\n")
	byTechnique := TechniqueControls(list)
	for _, t := range technique.All() {
		var ids, controls []string
		for _, id := range t.MITRE {
			ids = append(ids, fmt.Sprintf("[%s](%s)", id, mitreURL(id)))
		}
		for _, id := range byTechnique[t.ID] {
			controls = append(controls, fmt.Sprintf("[`%s`](#%s)", id, id))
		}
		corpus := t.NoCorpus
		if len(t.Corpus) > 0 {
			corpus = "`" + strings.Join(t.Corpus, "`, `") + "`"
		}
		fmt.Fprintf(&b, "| `%s`: %s | %s | %s | %s |\n", t.ID, t.Name, strings.Join(ids, ", "), strings.Join(controls, ", "), corpus)
	}
	return b.String()
}

// mitreURL links an ATT&CK id to its page. A sub-technique, as T1036.008,
// has the page techniques/T1036/008.
func mitreURL(id string) string {
	return "https://attack.mitre.org/techniques/" + strings.ReplaceAll(id, ".", "/") + "/"
}

// Attacks returns the list of the attack controls, each one linked to its
// section of controls.md.
func Attacks(list []Info) string {
	var b strings.Builder
	for _, c := range list {
		if c.Attack {
			fmt.Fprintf(&b, "- [`%s`](controls.md#%s): %s\n", c.ID, c.ID, c.Title)
		}
	}
	return b.String()
}

// RenderAttacks replaces the list of the attack controls of a doc.
func RenderAttacks(doc string, list []Info) (string, error) {
	return replaceBlock(doc, AttacksStart, AttacksEnd, Attacks(list))
}

// RenderDoc replaces the generated blocks of a controls doc.
func RenderDoc(doc string, list []Info) (string, error) {
	doc, err := replaceBlock(doc, TableStart, TableEnd, Table(list))
	if err != nil {
		return "", err
	}
	if doc, err = replaceBlock(doc, TechniqueStart, TechniqueEnd, Techniques(list)); err != nil {
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
