package code

import (
	"context"
	"fmt"

	"github.com/safedep/code/core"
	"github.com/safedep/vet/ent"
	"github.com/safedep/vet/pkg/storage"
)

// User define configuration for the scanner
type ScannerConfig struct {
	// First party application code directories
	AppDirectories []string

	// 3rd party imported code directories (e.g. Python virtual env, `node_modules` etc.)
	ImportDirectories []string

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
	// Create the file system walker with config

	// Initialize the plugins

	// Start the tree walker with plugins

	// Handle results from plugins

	// Use repository to persist the results

	return nil
}
