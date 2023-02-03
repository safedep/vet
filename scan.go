package main

import (
	"fmt"
	"os"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/parser"
	"github.com/safedep/vet/pkg/reporter"
	"github.com/safedep/vet/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	lockfiles           []string
	lockfileAs          string
	baseDirectory       string
	transitiveAnalysis  bool
	transitiveDepth     int
	concurrency         int
	dumpJsonManifestDir string
	celFilterExpression string
	markdownReportPath  string
	consoleReport       bool
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

	cmd.Flags().StringVarP(&baseDirectory, "directory", "D", wd,
		"The directory to scan for lockfiles")
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
	cmd.Flags().StringVarP(&markdownReportPath, "report-markdown", "", "",
		"Generate consolidated markdown report to file")
	cmd.Flags().BoolVarP(&consoleReport, "report-console", "", true,
		"Minimal summary of package manifest")

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
	err := internalStartScan()
	if err != nil {
		logger.Errorf("Scan completed with error: %v", err)
	}
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
		task, err := analyzer.NewCelFilterAnalyzer(celFilterExpression)
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
	}, enrichers, analyzers, reporters)

	var err error
	if len(lockfiles) > 0 {
		err = pmScanner.ScanLockfiles(lockfiles, lockfileAs)
	} else {
		err = pmScanner.ScanDirectory(baseDirectory)
	}

	return err
}
