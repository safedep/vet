package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/runner"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/printer"
	"github.com/safedep/vet/v2/report"
)

func newCapability(a *app.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "capability",
		Short: "Read the AI and crypto capabilities of a saved scan",
		Long: `Read the capabilities of a saved scan: the AI SDKs, models and agent
frameworks, and the cryptographic algorithms, protocols and certificates
that the code calls. A scan finds them when plugins.codeusage.enabled is
true.`,
	}
	c.AddCommand(newCapabilityList(a))
	return c
}

func newCapabilityList(a *app.App) *cobra.Command {
	var scan string
	var tags []string
	var f state.Flags
	c := &cobra.Command{
		Use:   "list",
		Short: "List the AI and crypto capabilities of a saved scan",
		Long: `List the capabilities of the last scan of the current directory, with
each call site: AI first, then weak crypto, then the other crypto. --tag
keeps the capabilities that have each tag, as ai, cryptography or weak.
--scan names another scan. -o json prints the whole capabilities.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			doc, err := runner.Load(cmd.Context(), a, scan, f)
			if err != nil {
				return err
			}
			var caps []*report.Capability
			for c, err := range doc.Capabilities(cmd.Context()) {
				if err != nil {
					return err
				}
				if hasTags(c, tags) {
					caps = append(caps, c)
				}
			}
			slices.SortStableFunc(caps, report.CompareCapabilities)
			p, err := a.Printer()
			if err != nil {
				return err
			}
			return p.Print(caps, capabilityRows(caps, doc.Header().Scan.Mode == report.ScanModeDelta))
		},
	}
	c.Flags().StringVar(&scan, "scan", "", "Scan id prefix, last, or report file. The default is the last scan")
	c.Flags().StringArrayVar(&tags, "tag", nil, "Keep the capabilities with this tag, as ai, cryptography or weak. Repeatable")
	c.Flags().StringVar(&f.StateDir, "state-dir", "", "Directory of the scan index and the scan files")
	return c
}

func hasTags(c *report.Capability, tags []string) bool {
	for _, t := range tags {
		if !c.HasTag(t) {
			return false
		}
	}
	return true
}

// capabilityRows has one row for each call site, so that a person can
// open each place in the code.
func capabilityRows(caps []*report.Capability, delta bool) printer.Rows {
	headers := []string{"KIND", "CAPABILITY", "TAGS"}
	if delta {
		headers = append(headers, "CHANGE")
	}
	rows := printer.Rows{
		Headers: append(headers, "WHERE", "CALL"),
		Empty:   "The scan has no capability. Set plugins.codeusage.enabled to true, then scan again.",
	}
	for _, c := range caps {
		row := []string{strings.ToUpper(string(c.Kind())), escape.Line(c.Name()), escape.Line(strings.Join(c.DetailTags(), ", "))}
		if delta {
			row = append(row, strings.ToLower(string(c.Change)))
		}
		if len(c.Occurrences) == 0 {
			rows.Rows = append(rows.Rows, append(row, "", ""))
			continue
		}
		for _, o := range c.Occurrences {
			where := o.File
			if o.Line > 0 {
				where = fmt.Sprintf("%s:%d", o.File, o.Line)
			}
			rows.Rows = append(rows.Rows, append(slices.Clone(row), escape.Line(where), escape.Line(o.Callee)))
		}
	}
	return rows
}
