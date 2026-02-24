package code

import (
	"context"
	"fmt"
	"regexp"

	callgraphv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/code/callgraph/v1"
	"github.com/safedep/code/core"
	"github.com/spf13/cobra"

	"github.com/safedep/vet/ent"
	"github.com/safedep/vet/internal/command"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/code"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/storage"
	xbomsig "github.com/safedep/vet/pkg/xbom/signatures"
	xbomtui "github.com/safedep/vet/pkg/xbom/tui"
	_ "github.com/safedep/vet/signatures" // triggers embed registration
)

var (
	dbPath                    string
	appDirs                   []string
	importDirs                []string
	excludePatterns           []string
	skipDependencyUsagePlugin bool
	skipSignatureMatching     bool
	noTUI                     bool
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
	cmd.Flags().StringArrayVarP(&excludePatterns, "exclude", "", []string{},
		"Name patterns to ignore while scanning a codebase")
	cmd.Flags().BoolVar(&skipDependencyUsagePlugin, "skip-dependency-usage-plugin", false, "Skip dependency usage plugin analysis")
	cmd.Flags().BoolVar(&skipSignatureMatching, "skip-signature-matching", false, "Skip xBOM signature matching during code scan")
	cmd.Flags().BoolVar(&noTUI, "no-tui", false, "Disable interactive TUI and use simple spinner output")

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

	excludePatternsRegexps := []*regexp.Regexp{}
	for _, pattern := range excludePatterns {
		excludePatternsRegexps = append(excludePatternsRegexps, regexp.MustCompile(pattern))
	}

	signaturesToMatch, err := loadSignatures()
	if err != nil {
		return fmt.Errorf("failed to load xBOM signatures: %w", err)
	}

	if !noTUI && xbomtui.IsTerminal() && !skipSignatureMatching && len(signaturesToMatch) > 0 {
		return runWithTUI(entSqliteStorage, allowedLanguages, excludePatternsRegexps, signaturesToMatch)
	}

	return runWithSpinner(entSqliteStorage, allowedLanguages, excludePatternsRegexps, signaturesToMatch)
}

func runWithTUI(
	entSqliteStorage storage.Storage[*ent.Client],
	allowedLanguages []core.Language,
	excludePatternsRegexps []*regexp.Regexp,
	signaturesToMatch []*callgraphv1.Signature,
) error {
	return xbomtui.Run(func(sink *xbomtui.EventSink) error {
		codeScanner, err := code.NewScanner(code.ScannerConfig{
			AppDirectories:            appDirs,
			ImportDirectories:         importDirs,
			ExcludePatterns:           excludePatternsRegexps,
			Languages:                 allowedLanguages,
			SkipDependencyUsagePlugin: skipDependencyUsagePlugin,
			SkipSignatureMatching:     skipSignatureMatching,
			SignaturesToMatch:         signaturesToMatch,
			Callbacks: &code.ScannerCallbackRegistry{
				OnScanStart:      func() error { return nil },
				OnScanEnd:        func() error { return nil },
				OnFileScanned:    sink.FileScanned,
				OnSignatureMatch: sink.MatchFound,
			},
		}, entSqliteStorage)
		if err != nil {
			return fmt.Errorf("failed to create code scanner: %w", err)
		}

		return codeScanner.Scan(context.Background())
	}, xbomtui.Config{})
}

func runWithSpinner(
	entSqliteStorage storage.Storage[*ent.Client],
	allowedLanguages []core.Language,
	excludePatternsRegexps []*regexp.Regexp,
	signaturesToMatch []*callgraphv1.Signature,
) error {
	codeScanner, err := code.NewScanner(code.ScannerConfig{
		AppDirectories:            appDirs,
		ImportDirectories:         importDirs,
		ExcludePatterns:           excludePatternsRegexps,
		Languages:                 allowedLanguages,
		SkipDependencyUsagePlugin: skipDependencyUsagePlugin,
		SkipSignatureMatching:     skipSignatureMatching,
		SignaturesToMatch:         signaturesToMatch,
		Callbacks: &code.ScannerCallbackRegistry{
			OnScanStart: func() error {
				ui.StartSpinner("Scanning code")
				return nil
			},
			OnScanEnd: func() error {
				ui.StopSpinner()
				ui.PrintSuccess("Code scanning completed. Run vet scan with code context using --code flag")
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

func loadSignatures() ([]*callgraphv1.Signature, error) {
	if skipSignatureMatching {
		return nil, nil
	}

	return xbomsig.LoadAllSignatures()
}
