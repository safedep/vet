package main

import (
	"fmt"
	"strings"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/code"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/spf13/cobra"
)

var (
	codeAppDirectories    = []string{}
	codeImportDirectories = []string{}
	codeGraphDatabase     string
	codeLanguage          string
)

func newCodeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "code",
		Short: "[EXPERIMENTAL] Perform code analysis with insights data",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	cmd.Flags().StringArrayVarP(&codeAppDirectories, "src", "", []string{}, "Source code root directory to analyze")
	cmd.Flags().StringArrayVarP(&codeImportDirectories, "imports", "", []string{}, "Language specific directory to find imported source")
	cmd.Flags().StringVarP(&codeGraphDatabase, "db", "", "", "Path to the database")
	cmd.Flags().StringVarP(&codeLanguage, "lang", "", "python", "Language of the source code")

	err := cmd.MarkFlagRequired("db")
	if err != nil {
		logger.Errorf("Failed to mark flag as required: %v", err)
	}

	cmd.AddCommand(newCodeCreateDatabaseCommand())
	cmd.AddCommand(newCodeImportReachabilityCommand())

	return cmd
}

func newCodeCreateDatabaseCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-db",
		Short: "Analyse code and create a database for further analysis",
		RunE: func(cmd *cobra.Command, args []string) error {
			startCreateDatabase()
			return nil
		},
	}

	return cmd
}

func newCodeImportReachabilityCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import-reachability",
		Short: "Analyse import reachability",
		RunE: func(cmd *cobra.Command, args []string) error {
			startImportReachability()
			return nil
		},
	}

	return cmd
}

func startCreateDatabase() {
	failOnError("code-create-db", internalStartCreateDatabase())
}

func startImportReachability() {
	failOnError("code-import-reachability-analysis", internalStartImportReachability())
}

func internalStartImportReachability() error {
	codePrintExperimentalWarning()

	if utils.IsEmptyString(codeGraphDatabase) {
		return fmt.Errorf("no database path provided")
	}

	// TODO: We need a CPG loader to load the CPG from the database
	// before invoking analysis modules

	return nil
}

func internalStartCreateDatabase() error {
	codePrintExperimentalWarning()
	logger.Debugf("Starting code analysis")

	if len(codeAppDirectories) == 0 {
		return fmt.Errorf("no source code directory provided")
	}

	if len(codeImportDirectories) == 0 {
		return fmt.Errorf("no import directory provided")
	}

	if utils.IsEmptyString(codeGraphDatabase) {
		return fmt.Errorf("no database path provided")
	}

	codeRepoCfg := code.FileSystemSourceRepositoryConfig{
		SourcePaths: codeAppDirectories,
		ImportPaths: codeImportDirectories,
	}

	codeRepo, err := code.NewFileSystemSourceRepository(codeRepoCfg)
	if err != nil {
		return fmt.Errorf("failed to create source repository: %w", err)
	}

	codeLang, err := codeGetLanguage()
	if err != nil {
		return fmt.Errorf("failed to create source language: %w", err)
	}

	codeRepo.ConfigureForLanguage(codeLang)

	cpgBuilderCfg := code.CpgBuilderConfig{
		Repository:   codeRepo,
		Language:     codeLang,
		DatabasePath: codeGraphDatabase,
	}

	cpgBuilder, err := code.NewCpgBuilder(cpgBuilderCfg)
	if err != nil {
		return fmt.Errorf("failed to create CPG builder: %w", err)
	}

	_, err = cpgBuilder.Build()
	if err != nil {
		return fmt.Errorf("failed to build CPG: %w", err)
	}

	logger.Debugf("Code analysis completed")
	return nil
}

func codePrintExperimentalWarning() {
	ui.PrintWarning("Code analysis is experimental and may have breaking change")
}

func codeGetLanguage() (code.SourceLanguage, error) {
	lang := strings.ToLower(codeLanguage)
	switch lang {
	case "python":
		return code.NewPythonSourceLanguage()
	default:
		return nil, fmt.Errorf("unsupported language: %s", codeLanguage)
	}
}
