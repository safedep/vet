package main

import (
	"fmt"
	"os"
	"time"

	"github.com/safedep/dry/utils"
	"github.com/spf13/cobra"

	"github.com/safedep/vet/internal/command"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/readers"
	"github.com/safedep/vet/pkg/reporter"
	"github.com/safedep/vet/pkg/scanner"
)

var (
	queryFilterExpression               string
	queryFilterSuiteFile                string
	queryFilterFailOnMatch              bool
	queryFilterV2Expression             string
	queryFilterV2SuiteFile              string
	queryPolicyExpression               string
	queryPolicySuiteFile                string
	queryLoadDirectory                  string
	queryEnableConsoleReport            bool
	queryEnableSummaryReport            bool
	querySummaryReportMaxAdvice         int
	querySummaryReportGroupByDirectDeps bool
	querySummaryUsedOnly                bool
	queryMarkdownReportPath             string
	queryMarkdownSummaryReportPath      string
	queryJSONReportPath                 string
	queryGraphReportPath                string
	queryCsvReportPath                  string
	queryReportDefectDojo               bool
	queryDefectDojoHostURL              string
	queryDefectDojoProductID            int
	querySarifReportPath                string
	querySarifIncludeVulns              bool
	querySarifIncludeMalware            bool
	queryCycloneDXReportPath            string
	queryCyclonedxReportApplicationName string
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
		"Filter and print packages using CEL (DEPRECATED: use --policy instead)")
	cmd.Flags().StringVarP(&queryFilterSuiteFile, "filter-suite", "", "",
		"Filter packages using CEL Filter Suite from file (DEPRECATED: use --policy-suite instead)")
	cmd.Flags().BoolVarP(&queryFilterFailOnMatch, "filter-fail", "", false,
		"Fail the command if filter matches any package (for security gate)")
	cmd.Flags().StringVarP(&queryFilterV2Expression, "filter-v2", "", "",
		"Filter and print packages using CEL with Insights v2 data model (alias for --policy)")
	cmd.Flags().StringVarP(&queryFilterV2SuiteFile, "filter-v2-suite", "", "",
		"Filter packages using CEL Filter Suite from file with Insights v2 data model (alias for --policy-suite)")
	cmd.Flags().StringVarP(&queryPolicyExpression, "policy", "", "",
		"Filter and print packages using CEL with Policy Input schema")
	cmd.Flags().StringVarP(&queryPolicySuiteFile, "policy-suite", "", "",
		"Filter packages using CEL Filter Suite from file with Policy Input schema")
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
	cmd.Flags().StringVarP(&queryJSONReportPath, "report-json", "", "",
		"Generate JSON report to file (EXPERIMENTAL)")
	cmd.Flags().StringVarP(&queryGraphReportPath, "report-graph", "", "",
		"Generate dependency graph as graphviz dot files to directory")
	cmd.Flags().StringVarP(&queryCsvReportPath, "report-csv", "", "",
		"Generate CSV report of filtered packages to file")
	cmd.Flags().BoolVarP(&queryReportDefectDojo, "report-defect-dojo", "", false, "Report to DefectDojo")
	cmd.Flags().StringVarP(&queryDefectDojoHostURL, "defect-dojo-host-url", "", "",
		"DefectDojo Host URL eg. http://localhost:8080")
	cmd.Flags().IntVarP(&queryDefectDojoProductID, "defect-dojo-product-id", "", -1, "DefectDojo Product ID")
	cmd.Flags().StringVarP(&querySarifReportPath, "report-sarif", "", "",
		"Generate SARIF report to file (*.sarif or *.sarif.json)")
	cmd.Flags().BoolVarP(&querySarifIncludeVulns, "report-sarif-vulns", "", true, "Include vulnerabilities in SARIF report (Enabled by default)")
	cmd.Flags().BoolVarP(&querySarifIncludeMalware, "report-sarif-malware", "", true, "Include malware in SARIF report (Enabled by default)")
	cmd.Flags().StringVarP(&queryCycloneDXReportPath, "report-cdx", "", "",
		"Generate CycloneDX report to file")
	cmd.Flags().StringVarP(&queryCyclonedxReportApplicationName, "report-cdx-app-name", "", "",
		"Application name used as root application component in CycloneDX BOM")

	// Add validations that should trigger a fail fast condition
	cmd.PreRun = func(cmd *cobra.Command, args []string) {
		err := func() error {
			if queryReportDefectDojo && (queryDefectDojoProductID == -1 || utils.IsEmptyString(queryDefectDojoHostURL)) {
				return fmt.Errorf("defect dojo Host URL & product ID are required for defect dojo report")
			}

			// Validate filter/policy flags
			if !utils.IsEmptyString(queryFilterV2Expression) && !utils.IsEmptyString(queryPolicyExpression) {
				return fmt.Errorf("cannot use both --filter-v2 and --policy flags simultaneously")
			}

			if !utils.IsEmptyString(queryFilterV2SuiteFile) && !utils.IsEmptyString(queryPolicySuiteFile) {
				return fmt.Errorf("cannot use both --filter-v2-suite and --policy-suite flags simultaneously")
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
	toolMetadata := reporter.ToolMetadata{
		Name:                 vetName,
		Version:              version,
		Purl:                 vetPurl,
		InformationURI:       vetInformationURI,
		VendorName:           vetVendorName,
		VendorInformationURI: vetVendorInformationURI,
	}

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

	// Handle filter-v2 and policy flags (they are aliases)
	policyExpr := queryPolicyExpression
	if !utils.IsEmptyString(queryFilterV2Expression) {
		policyExpr = queryFilterV2Expression
	}

	if !utils.IsEmptyString(policyExpr) {
		task, err := analyzer.NewCelFilterV2Analyzer(policyExpr,
			queryFilterFailOnMatch)
		if err != nil {
			return err
		}

		analyzers = append(analyzers, task)
	}

	// Handle filter-v2-suite and policy-suite flags (they are aliases)
	policySuite := queryPolicySuiteFile
	if !utils.IsEmptyString(queryFilterV2SuiteFile) {
		policySuite = queryFilterV2SuiteFile
	}

	if !utils.IsEmptyString(policySuite) {
		task, err := analyzer.NewCelFilterSuiteV2Analyzer(policySuite,
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
			Tool: toolMetadata,
			Path: queryMarkdownSummaryReportPath,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(queryJSONReportPath) {
		rp, err := reporter.NewJsonReportGenerator(reporter.JsonReportingConfig{
			Path: queryJSONReportPath,
			Tool: toolMetadata,
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
			Tool:           toolMetadata,
			IncludeVulns:   querySarifIncludeVulns,
			IncludeMalware: querySarifIncludeMalware,
			Path:           querySarifReportPath,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(queryCycloneDXReportPath) {
		if utils.IsEmptyString(queryCyclonedxReportApplicationName) {
			queryCyclonedxReportApplicationName, err = reader.ApplicationName()
			if err != nil {
				return err
			}
		}

		rp, err := reporter.NewCycloneDXReporter(reporter.CycloneDXReporterConfig{
			Tool:                     toolMetadata,
			Path:                     queryCycloneDXReportPath,
			ApplicationComponentName: queryCyclonedxReportApplicationName,
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

		engagementName := fmt.Sprintf("vet-report-%s", time.Now().Format("2006-01-02"))
		rp, err := reporter.NewDefectDojoReporter(reporter.DefectDojoReporterConfig{
			Tool:               toolMetadata,
			IncludeVulns:       true,
			IncludeMalware:     true,
			ProductID:          queryDefectDojoProductID,
			EngagementName:     engagementName,
			DefectDojoHostUrl:  queryDefectDojoHostURL,
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
