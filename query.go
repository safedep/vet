package main

import (
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/reporter"
	"github.com/safedep/vet/pkg/scanner"
	"github.com/spf13/cobra"
)

// We will re-use the variable declarations in scan.go
// since query.go is a subset of scan function where
// data is loaded from JSON instead of lockfiles and enriched
// with backend

func newQueryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query JSON dump and run filters or render reports",
		RunE: func(cmd *cobra.Command, args []string) error {
			startQuery()
			return nil
		},
	}

	cmd.Flags().StringVarP(&dumpJsonManifestDir, "from", "F", "",
		"The directory to load JSON dump files")
	cmd.Flags().StringVarP(&celFilterExpression, "filter", "", "",
		"Filter and print packages using CEL")
	cmd.Flags().BoolVarP(&consoleReport, "report-console", "", false,
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

	if !utils.IsEmptyString(celFilterExpression) {
		task, err := analyzer.NewCelFilterAnalyzer(celFilterExpression)
		if err != nil {
			return err
		}

		analyzers = append(analyzers, task)
	}

	if consoleReport {
		rp, err := reporter.NewConsoleReporter()
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	pmScanner := scanner.NewPackageManifestScanner(scanner.Config{
		TransitiveAnalysis: false,
	}, enrichers, analyzers, reporters)

	return pmScanner.ScanDumpDirectory(dumpJsonManifestDir)
}
