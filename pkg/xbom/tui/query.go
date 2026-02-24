package tui

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/safedep/vet/ent"
)

// QueryResultRenderer renders code query results to stdout using
// the existing TUI styles. It is non-interactive (no bubbletea).
type QueryResultRenderer struct {
	styles Styles
	width  int
}

// NewQueryResultRenderer creates a renderer that detects terminal width
// and uses the default color profile.
func NewQueryResultRenderer() *QueryResultRenderer {
	width := 120
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		width = w
	}

	return &QueryResultRenderer{
		styles: NewStyles(DefaultProfile),
		width:  width,
	}
}

// RenderMatches renders a flat table of signature matches with a footer.
// totalCount is the total number of matches in the DB (before limit).
func (r *QueryResultRenderer) RenderMatches(matches []*ent.CodeSignatureMatch, totalCount int) string {
	var b strings.Builder

	if len(matches) == 0 {
		b.WriteString(fmt.Sprintf("\n  %s\n",
			r.styles.Dim.Render(fmt.Sprintf("0 matches found (%d total in database)", totalCount))))
		return b.String()
	}

	truncated := len(matches) < totalCount

	showTags := r.width >= 100

	// Compute column widths from data
	maxSigID := len("Signature ID")
	maxLang := len("Language")
	maxFile := len("File Path")
	maxLine := len("Line")
	maxCall := len("Matched Call")

	for _, m := range matches {
		if len(m.SignatureID) > maxSigID {
			maxSigID = len(m.SignatureID)
		}
		if len(m.Language) > maxLang {
			maxLang = len(m.Language)
		}
		if len(m.FilePath) > maxFile {
			maxFile = len(m.FilePath)
		}
		lineStr := fmt.Sprintf("%d", m.Line)
		if len(lineStr) > maxLine {
			maxLine = len(lineStr)
		}
		if len(m.MatchedCall) > maxCall {
			maxCall = len(m.MatchedCall)
		}
	}

	// Cap column widths to fit terminal
	fixedCols := maxSigID + maxLang + maxLine + 12 // spacing between columns
	if showTags {
		fixedCols += 12 // rough space for tags column
	}
	availForFlexCols := r.width - fixedCols
	if availForFlexCols < 20 {
		availForFlexCols = 20
	}

	// Split available space between file path and matched call
	fileMax := availForFlexCols * 55 / 100
	callMax := availForFlexCols * 45 / 100
	if fileMax < 10 {
		fileMax = 10
	}
	if callMax < 10 {
		callMax = 10
	}
	if maxFile > fileMax {
		maxFile = fileMax
	}
	if maxCall > callMax {
		maxCall = callMax
	}

	// Header
	b.WriteString("\n")
	header := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s  %-*s",
		maxSigID, "Signature ID",
		maxLang, "Language",
		maxFile, "File Path",
		maxLine, "Line",
		maxCall, "Matched Call",
	)
	if showTags {
		header += "  Tags"
	}
	b.WriteString(r.styles.Title.Render(header))
	b.WriteString("\n")

	// Separator
	sep := fmt.Sprintf("  %s  %s  %s  %s  %s",
		strings.Repeat("─", maxSigID),
		strings.Repeat("─", maxLang),
		strings.Repeat("─", maxFile),
		strings.Repeat("─", maxLine),
		strings.Repeat("─", maxCall),
	)
	if showTags {
		sep += "  " + strings.Repeat("─", 10)
	}
	b.WriteString(r.styles.Dim.Render(sep))
	b.WriteString("\n")

	// Rows
	for _, m := range matches {
		filePath := truncateLeft(m.FilePath, maxFile)
		matchedCall := truncateRight(m.MatchedCall, maxCall)

		row := fmt.Sprintf("  %s  %s  %s  %s  %s",
			r.styles.SigName.Render(fmt.Sprintf("%-*s", maxSigID, m.SignatureID)),
			fmt.Sprintf("%-*s", maxLang, m.Language),
			r.styles.FileName.Render(fmt.Sprintf("%-*s", maxFile, filePath)),
			r.styles.Counter.Render(fmt.Sprintf("%-*d", maxLine, m.Line)),
			r.styles.Dim.Render(fmt.Sprintf("%-*s", maxCall, matchedCall)),
		)

		if showTags && len(m.Tags) > 0 {
			tagParts := make([]string, len(m.Tags))
			for i, tag := range m.Tags {
				tagParts[i] = r.styles.Counter.Render("[") +
					r.styles.Dim.Render(tag) +
					r.styles.Counter.Render("]")
			}
			row += "  " + strings.Join(tagParts, " ")
		}

		b.WriteString(row)
		b.WriteString("\n")
	}

	// Footer
	b.WriteString("\n")
	if truncated {
		footer := fmt.Sprintf("  %s %s",
			r.styles.StatValue.Render(fmt.Sprintf("%d", len(matches))),
			r.styles.StatLabel.Render(fmt.Sprintf("of %d matches shown (use --limit to adjust)",
				totalCount)),
		)
		b.WriteString(footer)
	} else {
		footer := fmt.Sprintf("  %s %s",
			r.styles.StatValue.Render(fmt.Sprintf("%d", len(matches))),
			r.styles.StatLabel.Render("matches found"),
		)
		b.WriteString(footer)
	}
	b.WriteString("\n")

	return b.String()
}

// truncateLeft truncates s from the left, prefixing with "..." if needed.
func truncateLeft(s string, max int) string {
	if max < 4 {
		max = 4
	}
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-max+3:]
}

// truncateRight truncates s from the right, suffixing with "..." if needed.
func truncateRight(s string, max int) string {
	if max < 4 {
		max = 4
	}
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
