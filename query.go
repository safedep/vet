package main

import (
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/reporter"
	"github.com/safedep/vet/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	queryFilterExpression    string
	queryFilterFailOnMatch   bool
	queryLoadDirectory       string
	queryEnableConsoleReport bool
	queryEnableSummaryReport bool
	queryMarkdownReportPath  string
)

func newQueryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query JSON dump and run filters or render reports",
		RunE: func(cmd *cobra.Command, args []string) error {
			startQuery()
			return nil
		},
	}

	cmd.Flags().StringVarP(&queryLoadDirectory, "from", "F", "",
		"The directory to load JSON dump files")
	cmd.Flags().StringVarP(&queryFilterExpression, "filter", "", "",
		"Filter and print packages using CEL")
	cmd.Flags().BoolVarP(&queryFilterFailOnMatch, "filter-fail", "", false,
		"Fail the command if filter matches any package (for security gate)")
	cmd.Flags().BoolVarP(&queryEnableConsoleReport, "report-console", "", false,
		"Minimal summary of package manifest")
	cmd.Flags().BoolVarP(&queryEnableSummaryReport, "report-summary", "", false,
		"Show an actionable summary based on scan data")
	cmd.Flags().StringVarP(&queryMarkdownReportPath, "report-markdown", "", "",
		"Generate markdown report to file")
	return cmd
}

func startQuery() {
	failOnError("query", internalStartQuery())
}

func internalStartQuery() error {
	analyzers := []analyzer.Analyzer{}
	reporters := []reporter.Reporter{}
	enrichers := []scanner.PackageMetaEnricher{}

	if !utils.IsEmptyString(queryFilterExpression) {
		task, err := analyzer.NewCelFilterAnalyzer(queryFilterExpression,
			queryFilterFailOnMatch)
		if err != nil {
			return err
		}

		analyzers = append(analyzers, task)
	}

	if queryEnableConsoleReport {
		rp, err := reporter.NewConsoleReporter()
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if queryEnableSummaryReport {
		rp, err := reporter.NewSummaryReporter()
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(queryMarkdownReportPath) {
		rp, err := reporter.NewMarkdownReportGenerator(reporter.MarkdownReportingConfig{
			Path: queryMarkdownReportPath,
		})

		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	pmScanner := scanner.NewPackageManifestScanner(scanner.Config{
		TransitiveAnalysis: false,
	}, enrichers, analyzers, reporters)

	redirectLogToFile(logFile)
	return pmScanner.ScanDumpDirectory(queryLoadDirectory)
}
