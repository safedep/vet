package table

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/safedep/vet/v2/internal/plugins/internal/render"
	"github.com/safedep/vet/v2/internal/tui/section"
	"github.com/safedep/vet/v2/internal/tui/style"
	"github.com/safedep/vet/v2/internal/tui/table"
	"github.com/safedep/vet/v2/report"
)

// toolKinds are the inventory kinds in table order, with their names for
// a person.
var toolKinds = []struct {
	kind      report.InventoryKind
	one, many string
}{
	{report.InventoryAITool, "AI tool", "AI tools"},
	{report.InventoryMCPServer, "MCP server", "MCP servers"},
	{report.InventorySkill, "agent skill", "agent skills"},
	{report.InventoryEditorPlugin, "editor plugin", "editor plugins"},
}

func toolRank(k report.InventoryKind) int {
	for i, t := range toolKinds {
		if t.kind == k {
			return i
		}
	}
	return len(toolKinds)
}

func toolName(k report.InventoryKind) string {
	if i := toolRank(k); i < len(toolKinds) {
		return toolKinds[i].one
	}
	return render.Text(string(k))
}

// toolCounts counts the tools of each kind, as "1 AI tool, 3 agent skills".
func toolCounts(tools []*report.InventoryItem) string {
	counts := map[report.InventoryKind]int{}
	for _, t := range tools {
		counts[t.Kind]++
	}
	var out []string
	for _, k := range toolKinds {
		if n := counts[k.kind]; n > 0 {
			out = append(out, plural(n, k.one, k.many))
		}
	}
	if n := len(tools) - countKnown(counts); n > 0 {
		out = append(out, plural(n, "other tool", "other tools"))
	}
	return strings.Join(out, ", ")
}

func countKnown(counts map[report.InventoryKind]int) int {
	n := 0
	for _, k := range toolKinds {
		n += counts[k.kind]
	}
	return n
}

// toolTable renders the tools that an endpoint audit finds: one row for
// each tool, by kind and then by name.
func (s Sink) toolTable(tools []*report.InventoryItem) []string {
	tools = slices.Clone(tools)
	slices.SortStableFunc(tools, func(a, b *report.InventoryItem) int {
		return cmp.Or(cmp.Compare(toolRank(a.Kind), toolRank(b.Kind)), cmp.Compare(a.Name, b.Name))
	})
	shown := tools
	if s.limit > 0 && len(shown) > s.limit {
		shown = shown[:s.limit]
	}
	tbl := table.New().Headers("KIND", "NAME", "VERSION", "CLIENT", "PATH").
		Columns(table.Column{}, table.Column{}, table.Column{Drop: 1}, table.Column{Drop: 2}, table.Column{Fit: table.CutLeft})
	for _, t := range shown {
		tbl.Row(toolName(t.Kind), render.Text(t.Name), render.Text(t.Version), render.Text(t.Client), render.Text(t.Path))
	}
	parts := []string{style.Heading("Tools: " + toolCounts(tools)), tbl.Render()}
	if more := len(tools) - len(shown); more > 0 {
		parts = append(parts, section.Hint(fmt.Sprintf("%s. vet report show --all lists each one.", plural(more, "more tool", "more tools"))))
	}
	return parts
}
