package reporter

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/safedep/dry/semver"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/readers"
)

type consoleReporter struct{}

func NewConsoleReporter() (Reporter, error) {
	return &consoleReporter{}, nil
}

func (r *consoleReporter) Name() string {
	return "Console Report Generator"
}

func (r *consoleReporter) AddManifest(manifest *models.PackageManifest) {
	tbl := table.NewWriter()
	tbl.SetOutputMirror(os.Stdout)
	tbl.SetStyle(table.StyleLight)

	tbl.AppendHeader(table.Row{"Package", "Attribute", "Summary"})
	readers.NewManifestModelReader(manifest).EnumPackages(func(pkg *models.Package) error {
		r.report(tbl, pkg)
		return nil
	})

	fmt.Print(text.Bold.Sprint("Manifest: ", text.FgBlue.Sprint(manifest.Path)))
	fmt.Print("\n")

	tbl.Render()
}

func (r *consoleReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
}

func (r *consoleReporter) AddPolicyEvent(event *policy.PolicyEvent) {
}

func (r *consoleReporter) Finish() error {
	return nil
}

func (r *consoleReporter) report(tbl table.Writer, pkg *models.Package) {
	insight := utils.SafelyGetValue(pkg.Insights)

	headerAppended := false
	headerAppender := func() {
		if headerAppended {
			return
		}

		// Header for this package
		tbl.AppendRow(table.Row{
			fmt.Sprintf("%s/%s", pkg.PackageDetails.Name, pkg.PackageDetails.Version),
			"", "",
		})

		headerAppended = true
	}

	// Report vulnerabilities
	sm := map[string]int{"CRITICAL": 0, "HIGH": 0}
	for _, vuln := range utils.SafelyGetValue(insight.Vulnerabilities) {
		for _, s := range utils.SafelyGetValue(vuln.Severities) {
			risk := string(utils.SafelyGetValue(s.Risk))
			if (risk == "CRITICAL") || (risk == "HIGH") {
				sm[risk] += 1
			}
		}
	}

	if (sm["CRITICAL"] > 0) || (sm["HIGH"] > 0) {
		headerAppender()
		tbl.AppendRow(table.Row{"",
			text.Bold.Sprint(text.BgRed.Sprint("Vulnerability")),
			fmt.Sprintf("Critical:%d High:%d",
				sm["CRITICAL"], sm["HIGH"])})
	}

	// Popularity
	projects := utils.SafelyGetValue(insight.Projects)
	if len(projects) > 0 {
		p := projects[0]

		sc := utils.SafelyGetValue(p.Stars)
		ic := utils.SafelyGetValue(p.Issues)

		if (sc > 0) && (sc < 10) && (ic > 0) && (ic < 5) {
			headerAppender()
			tbl.AppendRow(table.Row{"",
				text.Bold.Sprint("Low Popularity"),
				fmt.Sprintf("Stars:%d Issues:%d", sc, ic)})
		}
	}

	// High version drift
	version := pkg.PackageDetails.Version
	latestVersion := utils.SafelyGetValue(insight.PackageCurrentVersion)

	driftType, _ := semver.Diff(version, latestVersion)
	if driftType.IsMajor() {
		headerAppender()
		tbl.AppendRow(table.Row{"",
			text.Bold.Sprint("Version Drift"),
			fmt.Sprintf("%s > %s", version, latestVersion),
		})
	}

	if headerAppended {
		tbl.AppendSeparator()
	}
}
