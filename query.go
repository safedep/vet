package main

import (
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/reporter"
	"github.com/safedep/vet/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	queryFilterExpression    string
	queryLoadDirectory       string
	queryEnableConsoleReport bool
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
	cmd.Flags().BoolVarP(&queryEnableConsoleReport, "report-console", "", false,
		"Minimal summary of package manifest")

	return cmd
}

func startQuery() {
	err := internalStartQuery()
	if err != nil {
		logger.Errorf("Query completed with error: %v", err)
	}
}

func internalStartQuery() error {
	analyzers := []analyzer.Analyzer{}
	reporters := []reporter.Reporter{}
	enrichers := []scanner.PackageMetaEnricher{}

	if !utils.IsEmptyString(queryFilterExpression) {
		task, err := analyzer.NewCelFilterAnalyzer(queryFilterExpression)
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

	pmScanner := scanner.NewPackageManifestScanner(scanner.Config{
		TransitiveAnalysis: false,
	}, enrichers, analyzers, reporters)

	return pmScanner.ScanDumpDirectory(queryLoadDirectory)
}
