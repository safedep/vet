package main

import (
	"fmt"
	"os"
	"time"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/internal/command"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/readers"
	"github.com/safedep/vet/pkg/reporter"
	"github.com/safedep/vet/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	queryFilterExpression               string
	queryFilterSuiteFile                string
	queryFilterFailOnMatch              bool
	queryLoadDirectory                  string
	queryEnableConsoleReport            bool
	queryEnableSummaryReport            bool
	querySummaryReportMaxAdvice         int
	querySummaryReportGroupByDirectDeps bool
	querySummaryUsedOnly                bool
	queryMarkdownReportPath             string
	queryMarkdownSummaryReportPath      string
	queryJsonReportPath                 string
	queryGraphReportPath                string
	queryCsvReportPath                  string
	queryReportDefectDojo               bool
	queryDefectDojoProductID            int
	querySarifReportPath                string
	queryExceptionsFile                 string
	queryExceptionsTill                 string
	queryExceptionsFilter               string

	queryDefaultExceptionExpiry = time.Now().Add(90 * 24 * time.Hour)
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
	cmd.Flags().StringVarP(&queryFilterSuiteFile, "filter-suite", "", "",
		"Filter packages using CEL Filter Suite from file")
	cmd.Flags().BoolVarP(&queryFilterFailOnMatch, "filter-fail", "", false,
		"Fail the command if filter matches any package (for security gate)")
	cmd.Flags().StringVarP(&queryExceptionsFile, "exceptions-generate", "", "",
		"Generate exception records to file (YAML)")
	cmd.Flags().StringVarP(&queryExceptionsTill, "exceptions-till", "",
		queryDefaultExceptionExpiry.Format("2006-01-02"),
		"Generated exceptions are valid till")
	cmd.Flags().StringVarP(&queryExceptionsFilter, "exceptions-filter", "", "",
		"Generate exception records for packages matching filter")
	cmd.Flags().BoolVarP(&queryEnableConsoleReport, "report-console", "", false,
		"Minimal summary of package manifest")
	cmd.Flags().BoolVarP(&queryEnableSummaryReport, "report-summary", "", false,
		"Show an actionable summary based on scan data")
	cmd.Flags().IntVarP(&querySummaryReportMaxAdvice, "report-summary-max-advice", "", 5,
		"Maximum number of package risk advice to show")
	cmd.Flags().BoolVarP(&querySummaryReportGroupByDirectDeps, "report-summary-group-by-direct-deps", "", false,
		"Group summary by direct dependencies")
	cmd.Flags().BoolVarP(&querySummaryUsedOnly, "report-summary-used-only", "", false,
		"Show only packages that are used in code (requires code analysis during scan)")
	cmd.Flags().StringVarP(&queryMarkdownReportPath, "report-markdown", "", "",
		"Generate markdown report to file")
	cmd.Flags().StringVarP(&queryMarkdownSummaryReportPath, "report-markdown-summary", "", "",
		"Generate markdown summary report to file")
	cmd.Flags().StringVarP(&queryJsonReportPath, "report-json", "", "",
		"Generate JSON report to file (EXPERIMENTAL)")
	cmd.Flags().StringVarP(&queryGraphReportPath, "report-graph", "", "",
		"Generate dependency graph as graphviz dot files to directory")
	cmd.Flags().StringVarP(&queryCsvReportPath, "report-csv", "", "",
		"Generate CSV report of filtered packages to file")
	cmd.Flags().BoolVarP(&queryReportDefectDojo, "report-defect-dojo", "", false, "Report to DefectDojo")
	cmd.Flags().IntVarP(&queryDefectDojoProductID, "defect-dojo-product-id", "", -1, "DefectDojo Product ID")
	cmd.Flags().StringVarP(&querySarifReportPath, "report-sarif", "", "",
		"Generate SARIF report to file")

	// Add validations that should trigger a fail fast condition
	cmd.PreRun = func(cmd *cobra.Command, args []string) {
		err := func() error {
			if queryReportDefectDojo && queryDefectDojoProductID == -1 {
				return fmt.Errorf("defect dojo product ID is required for defect dojo report")
			}

			return nil
		}()

		command.FailOnError("pre-scan", err)
	}
	return cmd
}

func startQuery() {
	command.FailOnError("query", internalStartQuery())
}

func internalStartQuery() error {
	readerList := []readers.PackageManifestReader{}
	analyzers := []analyzer.Analyzer{}
	reporters := []reporter.Reporter{}
	enrichers := []scanner.PackageMetaEnricher{}

	reader, err := readers.NewJsonDumpReader(queryLoadDirectory)
	if err != nil {
		return err
	}

	readerList = append(readerList, reader)

	if !utils.IsEmptyString(queryFilterExpression) {
		task, err := analyzer.NewCelFilterAnalyzer(queryFilterExpression,
			queryFilterFailOnMatch)
		if err != nil {
			return err
		}

		analyzers = append(analyzers, task)
	}

	if !utils.IsEmptyString(queryFilterSuiteFile) {
		task, err := analyzer.NewCelFilterSuiteAnalyzer(queryFilterSuiteFile,
			queryFilterFailOnMatch)
		if err != nil {
			return err
		}

		analyzers = append(analyzers, task)
	}

	if !utils.IsEmptyString(queryExceptionsFile) {
		task, err := analyzer.NewExceptionsGenerator(analyzer.ExceptionsGeneratorConfig{
			Path:      queryExceptionsFile,
			ExpiresOn: queryExceptionsTill,
			Filter:    queryExceptionsFilter,
		})
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
		rp, err := reporter.NewSummaryReporter(reporter.SummaryReporterConfig{
			MaxAdvice:                    querySummaryReportMaxAdvice,
			GroupByDirectDependency:      querySummaryReportGroupByDirectDeps,
			ShowOnlyPackagesWithEvidence: querySummaryUsedOnly,
		})
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

	if !utils.IsEmptyString(queryMarkdownSummaryReportPath) {
		rp, err := reporter.NewMarkdownSummaryReporter(reporter.MarkdownSummaryReporterConfig{
			Path: queryMarkdownSummaryReportPath,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(queryJsonReportPath) {
		rp, err := reporter.NewJsonReportGenerator(reporter.JsonReportingConfig{
			Path: queryJsonReportPath,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(queryCsvReportPath) {
		rp, err := reporter.NewCsvReporter(reporter.CsvReportingConfig{
			Path: queryCsvReportPath,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(queryGraphReportPath) {
		rp, err := reporter.NewDotGraphReporter(queryGraphReportPath)
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(querySarifReportPath) {
		rp, err := reporter.NewSarifReporter(reporter.SarifReporterConfig{
			Path: querySarifReportPath,
			Tool: reporter.SarifToolMetadata{
				Name:    "vet",
				Version: version,
			},
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if queryReportDefectDojo {
		defectDojoApiV2Key := os.Getenv("DEFECT_DOJO_APIV2_KEY")
		if utils.IsEmptyString(defectDojoApiV2Key) {
			return fmt.Errorf("please set DEFECT_DOJO_APIV2_KEY environment variable to enable defect-dojo reporting")
		}

		defectDojoHostUrl := os.Getenv("DEFECT_DOJO_HOST_URL")
		if utils.IsEmptyString(defectDojoHostUrl) {
			defectDojoHostUrl = reporter.DefaultDefectDojoHostUrl
		}

		engagementName := fmt.Sprintf("vet-report-%s", time.Now().Format("2006-01-02"))
		rp, err := reporter.NewDefectDojoReporter(reporter.DefectDojoReporterConfig{
			Tool: reporter.DefectDojoToolMetadata{
				Name:    "vet",
				Version: version,
			},
			ProductID:          queryDefectDojoProductID,
			EngagementName:     engagementName,
			DefectDojoHostUrl:  defectDojoHostUrl,
			DefectDojoApiV2Key: defectDojoApiV2Key,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	pmScanner := scanner.NewPackageManifestScanner(scanner.Config{
		TransitiveAnalysis: false,
	}, readerList, enrichers, analyzers, reporters)

	redirectLogToFile(logFile)
	return pmScanner.Start()
}
