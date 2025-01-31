package code

import (
	"context"
	"fmt"

	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/code"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/storage"
	"github.com/spf13/cobra"
)

var (
	dbPath                    string
	dirsToWalk                []string
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

	cmd.Flags().StringVar(&dbPath, "db", "vet.db", "Path to create the sqlite database")
	cmd.Flags().StringArrayVar(&dirsToWalk, "dir", []string{"."}, "Directories to scan for code files")
	cmd.Flags().StringArrayVar(&importDirs, "import-dir", []string{}, "Directories to scan for import files")
	cmd.Flags().BoolVar(&skipDependencyUsagePlugin, "skip-dependency-usage-plugin", false, "Skip dependency usage plugin analysis")

	return cmd
}

func startScan() {
	failOnError("scan", internalStartScan())
}

func internalStartScan() error {
	allowedLanguages, err := getLanguagesFromCodes(languageCodes)
	if err != nil {
		logger.Fatalf("Failed to get languages from codes: %v", err)
		return err
	}

	entSqliteStorage, err := storage.NewEntSqliteStorage(storage.EntSqliteClientConfig{
		Path:               dbPath,
		ReadOnly:           false,
		SkipSchemaCreation: false,
	})
	if err != nil {
		logger.Fatalf("Failed to create ent sqlite storage: %v", err)
		return err
	}

	codeScanner, err := code.NewScanner(code.ScannerConfig{
		AppDirectories:            dirsToWalk,
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
				fmt.Println("Scan complete.")
				return nil
			},
		},
	}, entSqliteStorage)
	if err != nil {
		logger.Fatalf("Failed to create code scanner: %v", err)
		return err
	}

	return codeScanner.Scan(context.Background())
}
