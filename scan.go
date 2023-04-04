package main

import (
	"fmt"
	"os"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
	"github.com/safedep/vet/pkg/reporter"
	"github.com/safedep/vet/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	lockfiles                   []string
	lockfileAs                  string
	baseDirectory               string
	scanExclude                 []string
	transitiveAnalysis          bool
	transitiveDepth             int
	concurrency                 int
	dumpJsonManifestDir         string
	celFilterExpression         string
	celFilterSuiteFile          string
	celFilterFailOnMatch        bool
	markdownReportPath          string
	consoleReport               bool
	summaryReport               bool
	silentScan                  bool
	disableAuthVerifyBeforeScan bool
)

func newScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan and analyse package manifests",
		RunE: func(cmd *cobra.Command, args []string) error {
			startScan()
			return nil
		},
	}

	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	cmd.Flags().BoolVarP(&silentScan, "silent", "s", false,
		"Silent scan to prevent rendering UI")
	cmd.Flags().StringVarP(&baseDirectory, "directory", "D", wd,
		"The directory to scan for lockfiles")
	cmd.Flags().StringArrayVarP(&scanExclude, "exclude", "", []string{},
		"Name patterns to ignore while scanning a directory")
	cmd.Flags().StringArrayVarP(&lockfiles, "lockfiles", "L", []string{},
		"List of lockfiles to scan")
	cmd.Flags().StringVarP(&lockfileAs, "lockfile-as", "", "",
		"Parser to use for the lockfile (vet scan parsers to list)")
	cmd.Flags().BoolVarP(&transitiveAnalysis, "transitive", "", false,
		"Analyze transitive dependencies")
	cmd.Flags().IntVarP(&transitiveDepth, "transitive-depth", "", 2,
		"Analyze transitive dependencies till depth")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "C", 5,
		"Number of concurrent analysis to run")
	cmd.Flags().StringVarP(&dumpJsonManifestDir, "json-dump-dir", "", "",
		"Dump enriched package manifests as JSON files to dir")
	cmd.Flags().StringVarP(&celFilterExpression, "filter", "", "",
		"Filter and print packages using CEL")
	cmd.Flags().StringVarP(&celFilterSuiteFile, "filter-suite", "", "",
		"Filter packages using CEL Filter Suite from file")
	cmd.Flags().BoolVarP(&celFilterFailOnMatch, "filter-fail", "", false,
		"Fail the scan if the filter match any package (security gate)")
	cmd.Flags().BoolVarP(&disableAuthVerifyBeforeScan, "no-verify-auth", "", false,
		"Do not verify auth token before starting scan")
	cmd.Flags().StringVarP(&markdownReportPath, "report-markdown", "", "",
		"Generate consolidated markdown report to file")
	cmd.Flags().BoolVarP(&consoleReport, "report-console", "", false,
		"Print a report to the console")
	cmd.Flags().BoolVarP(&summaryReport, "report-summary", "", true,
		"Print a summary report with actionable advice")

	cmd.AddCommand(listParsersCommand())
	return cmd
}

func listParsersCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "parsers",
		Short: "List available lockfile parsers",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Available Lockfile Parsers\n")
			fmt.Printf("==========================\n\n")

			for idx, p := range parser.List() {
				fmt.Printf("[%d] %s\n", idx, p)
			}

			return nil
		},
	}
}

func startScan() {
	if !disableAuthVerifyBeforeScan {
		failOnError("auth/verify", auth.Verify(&auth.VerifyConfig{
			ControlPlaneApiUrl: auth.DefaultControlPlaneApiUrl(),
		}))
	}

	failOnError("scan", internalStartScan())
}

func internalStartScan() error {
	analyzers := []analyzer.Analyzer{}
	if !utils.IsEmptyString(dumpJsonManifestDir) {
		task, err := analyzer.NewJsonDumperAnalyzer(dumpJsonManifestDir)
		if err != nil {
			return err
		}

		analyzers = append(analyzers, task)
	}

	if !utils.IsEmptyString(celFilterExpression) {
		task, err := analyzer.NewCelFilterAnalyzer(celFilterExpression,
			celFilterFailOnMatch)
		if err != nil {
			return err
		}

		analyzers = append(analyzers, task)
	}

	if !utils.IsEmptyString(celFilterSuiteFile) {
		task, err := analyzer.NewCelFilterSuiteAnalyzer(celFilterSuiteFile,
			celFilterFailOnMatch)
		if err != nil {
			return err
		}

		analyzers = append(analyzers, task)
	}

	reporters := []reporter.Reporter{}
	if consoleReport {
		rp, err := reporter.NewConsoleReporter()
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if summaryReport {
		rp, err := reporter.NewSummaryReporter()
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(markdownReportPath) {
		rp, err := reporter.NewMarkdownReportGenerator(reporter.MarkdownReportingConfig{
			Path: markdownReportPath,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	enrichers := []scanner.PackageMetaEnricher{
		scanner.NewInsightBasedPackageEnricher(),
	}

	pmScanner := scanner.NewPackageManifestScanner(scanner.Config{
		TransitiveAnalysis: transitiveAnalysis,
		TransitiveDepth:    transitiveDepth,
		ConcurrentAnalyzer: concurrency,
		ExcludePatterns:    scanExclude,
	}, enrichers, analyzers, reporters)

	// Redirect log to files to create space for UI rendering
	redirectLogToFile(logFile)

	// Trackers to handle UI
	var packageManifestTracker any
	var packageTracker any

	pmScanner.WithCallbacks(scanner.ScannerCallbacks{
		OnStart: func(manifests []*models.PackageManifest) {
			if !silentScan {
				ui.StartProgressWriter()
			}

			var tm, tp int
			for _, m := range manifests {
				tm += 1
				tp += len(m.Packages)
			}

			packageManifestTracker = ui.TrackProgress("Scanning manifests", tm)
			packageTracker = ui.TrackProgress("Scanning packages", tp)
		},
		OnAddTransitivePackage: func(pkg *models.Package) {
			ui.IncrementTrackerTotal(packageTracker, 1)
		},
		OnDoneManifest: func(manifest *models.PackageManifest) {
			ui.IncrementProgress(packageManifestTracker, 1)
		},
		OnDonePackage: func(pkg *models.Package) {
			ui.IncrementProgress(packageTracker, 1)
		},
		BeforeFinish: func() {
			ui.MarkTrackerAsDone(packageManifestTracker)
			ui.MarkTrackerAsDone(packageTracker)
			ui.StopProgressWriter()
		},
	})

	var err error
	if len(lockfiles) > 0 {
		err = pmScanner.ScanLockfiles(lockfiles, lockfileAs)
	} else {
		err = pmScanner.ScanDirectory(baseDirectory)
	}

	return err
}
