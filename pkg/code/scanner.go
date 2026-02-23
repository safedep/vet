package code

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	callgraphv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/code/callgraph/v1"
	"github.com/safedep/code/core"
	"github.com/safedep/code/fs"
	"github.com/safedep/code/parser"
	"github.com/safedep/code/plugin"
	"github.com/safedep/code/plugin/callgraph"
	"github.com/safedep/code/plugin/depsusage"

	"github.com/safedep/vet/ent"
	"github.com/safedep/vet/pkg/storage"
)

// ScannerConfig define configuration for the scanner
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

	// Signature matching configuration
	SkipSignatureMatching bool
	SignaturesToMatch     []*callgraphv1.Signature
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

	if !s.config.SkipSignatureMatching && len(s.config.SignaturesToMatch) > 0 {
		signatureMatcher, err := callgraph.NewSignatureMatcher(s.config.SignaturesToMatch)
		if err != nil {
			return fmt.Errorf("failed to create signature matcher: %w", err)
		}

		var cgCallback callgraph.CallgraphCallback = func(ctx context.Context, cg *callgraph.CallGraph) error {
			treeData, err := cg.Tree.Data()
			if err != nil {
				return fmt.Errorf("failed to get tree data: %w", err)
			}

			matches, err := signatureMatcher.MatchSignatures(cg)
			if err != nil {
				return fmt.Errorf("failed to match signatures: %w", err)
			}

			for _, match := range matches {
				for _, condition := range match.MatchedConditions {
					for _, evidence := range condition.Evidences {
						metadata := evidence.Metadata(treeData)
						data := &SignatureMatchData{
							SignatureID:          match.MatchedSignature.Id,
							SignatureVendor:      match.MatchedSignature.GetVendor(),
							SignatureProduct:     match.MatchedSignature.GetProduct(),
							SignatureService:     match.MatchedSignature.GetService(),
							SignatureDescription: match.MatchedSignature.GetDescription(),
							Tags:                 match.MatchedSignature.Tags,
							FilePath:             match.FilePath,
							Language:             string(match.MatchedLanguageCode),
							CalleeNamespace:      metadata.CalleeNamespace,
							MatchedCall:          condition.Condition.GetValue(),
						}

						if metadata.CallerIdentifierMetadata != nil {
							data.Line = uint(metadata.CallerIdentifierMetadata.StartLine + 1)
							data.Column = uint(metadata.CallerIdentifierMetadata.StartColumn + 1)
						}

						data.PackageHint = s.derivePackageHint(match.FilePath)

						if _, err := s.writer.SaveSignatureMatch(ctx, data); err != nil {
							return fmt.Errorf("failed to save signature match: %w", err)
						}
					}
				}
			}
			return nil
		}
		plugins = append(plugins, callgraph.NewCallGraphPlugin(cgCallback))
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

// derivePackageHint checks if filePath is under any configured ImportDirectory
// and extracts the first path component after the import directory as the package hint.
// Returns empty string for app-level findings (files not under import directories).
func (s *scanner) derivePackageHint(filePath string) string {
	for _, importDir := range s.config.ImportDirectories {
		absImportDir, err := filepath.Abs(importDir)
		if err != nil {
			continue
		}
		absFilePath, err := filepath.Abs(filePath)
		if err != nil {
			continue
		}

		if !strings.HasPrefix(absFilePath, absImportDir+string(filepath.Separator)) {
			continue
		}

		rel, err := filepath.Rel(absImportDir, absFilePath)
		if err != nil {
			continue
		}

		// Extract first component of the relative path as the package hint
		parts := strings.SplitN(filepath.ToSlash(rel), "/", 2)
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}

	return ""
}
