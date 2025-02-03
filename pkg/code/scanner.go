package code

import (
	"context"
	"fmt"
	"regexp"

	"github.com/safedep/code/core"
	"github.com/safedep/code/fs"
	"github.com/safedep/code/parser"
	"github.com/safedep/code/plugin"
	"github.com/safedep/code/plugin/depsusage"
	"github.com/safedep/vet/ent"
	"github.com/safedep/vet/pkg/storage"
)

// User define configuration for the scanner
type ScannerConfig struct {
	// First party application code directories
	AppDirectories []string

	// 3rd party imported code directories (e.g. Python virtual env, `node_modules` etc.)
	ImportDirectories []string

	// Regular expressions to exclude files or directories
	// from traversal
	ExcludePatterns []*regexp.Regexp

	// Languages to scan
	Languages []core.Language

	// Define callbacks if required
	Callbacks *ScannerCallbackRegistry

	// Plugin specific configuration
	SkipDependencyUsagePlugin bool
}

type ScannerCallbackRegistry struct {
	// On start of scan
	OnScanStart func() error

	// On end of scan
	OnScanEnd func() error
}

// Scanner defines the contract for implementing a code scanner. The purpose
// of code scanner is to scan configured directories for code files,
// parse them, process them with plugins, persist the plugin results. It
// should also expose the necessary callbacks for interactive applications
// to show progress to user.
type Scanner interface {
	Scan(context.Context) error
}

type scanner struct {
	config  ScannerConfig
	storage storage.Storage[*ent.Client]
	writer  writerRepository
}

func NewScanner(config ScannerConfig, storage storage.Storage[*ent.Client]) (Scanner, error) {
	client, err := storage.Client()
	if err != nil {
		return nil, fmt.Errorf("failed to get ent client: %w", err)
	}

	writer, err := newWriterRepository(client)
	if err != nil {
		return nil, fmt.Errorf("failed to create writer repository: %w", err)
	}

	return &scanner{
		config:  config,
		storage: storage,
		writer:  writer,
	}, nil
}

func (s *scanner) Scan(ctx context.Context) error {
	err := s.config.Callbacks.OnScanStart()
	if err != nil {
		return fmt.Errorf("failed to execute OnScanStart callback: %w", err)
	}

	fileSystem, err := fs.NewLocalFileSystem(fs.LocalFileSystemConfig{
		AppDirectories:    s.config.AppDirectories,
		ImportDirectories: s.config.ImportDirectories,
		ExcludePatterns:   s.config.ExcludePatterns,
	})
	if err != nil {
		return fmt.Errorf("failed to create file system: %w", err)
	}

	walker, err := fs.NewSourceWalker(fs.SourceWalkerConfig{}, s.config.Languages)
	if err != nil {
		return fmt.Errorf("failed to create source walker: %w", err)
	}

	treeWalker, err := parser.NewWalkingParser(walker, s.config.Languages)
	if err != nil {
		return fmt.Errorf("failed to create tree walker: %w", err)
	}

	// Configure plugins
	plugins := []core.Plugin{}

	if !s.config.SkipDependencyUsagePlugin {
		var usageCallback depsusage.DependencyUsageCallback = func(ctx context.Context, evidence *depsusage.UsageEvidence) error {
			_, err := s.writer.SaveDependencyUsage(ctx, evidence)
			if err != nil {
				return fmt.Errorf("failed to save dependency usage: %w", err)
			}
			return nil
		}
		plugins = append(plugins, depsusage.NewDependencyUsagePlugin(usageCallback))
	}

	// Execute plugins
	pluginExecutor, err := plugin.NewTreeWalkPluginExecutor(treeWalker, plugins)
	if err != nil {
		return fmt.Errorf("failed to create plugin executor: %w", err)
	}

	err = pluginExecutor.Execute(ctx, fileSystem)
	if err != nil {
		return fmt.Errorf("failed to execute plugin: %w", err)
	}

	err = s.config.Callbacks.OnScanEnd()
	if err != nil {
		return fmt.Errorf("failed to execute OnScanEnd callback: %w", err)
	}

	return nil
}
