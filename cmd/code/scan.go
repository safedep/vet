package code

import (
	"context"

	"github.com/safedep/vet/internal/command"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/code"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/storage"
	"github.com/spf13/cobra"
)

var (
	dbPath                    string
	appDirs                   []string
	importDirs                []string
	skipDependencyUsagePlugin bool
)

func newScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan source code",
		RunE: func(cmd *cobra.Command, args []string) error {
			startScan()
			return nil
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "", "Path to create the sqlite database")
	cmd.Flags().StringArrayVar(&appDirs, "app", []string{"."}, "Directories to scan for application code files")
	cmd.Flags().StringArrayVar(&importDirs, "import-dir", []string{}, "Directories to scan for import files")
	cmd.Flags().BoolVar(&skipDependencyUsagePlugin, "skip-dependency-usage-plugin", false, "Skip dependency usage plugin analysis")

	_ = cmd.MarkFlagRequired("db")

	return cmd
}

func startScan() {
	command.FailOnError("scan", internalStartScan())
}

func internalStartScan() error {
	allowedLanguages, err := getLanguagesFromCodes(languageCodes)
	if err != nil {
		logger.Fatalf("failed to get languages from codes: %v", err)
		return err
	}

	entSqliteStorage, err := storage.NewEntSqliteStorage(storage.EntSqliteClientConfig{
		Path:               dbPath,
		ReadOnly:           false,
		SkipSchemaCreation: false,
	})
	if err != nil {
		logger.Fatalf("failed to create ent sqlite storage: %v", err)
		return err
	}

	codeScanner, err := code.NewScanner(code.ScannerConfig{
		AppDirectories:            appDirs,
		ImportDirectories:         importDirs,
		Languages:                 allowedLanguages,
		SkipDependencyUsagePlugin: skipDependencyUsagePlugin,
		Callbacks: &code.ScannerCallbackRegistry{
			OnScanStart: func() error {
				ui.StartSpinner("Scanning code")
				return nil
			},
			OnScanEnd: func() error {
				ui.StopSpinner()
				ui.PrintSuccess("Code scanning completed")
				return nil
			},
		},
	}, entSqliteStorage)
	if err != nil {
		logger.Fatalf("failed to create code scanner: %v", err)
		return err
	}

	return codeScanner.Scan(context.Background())
}
