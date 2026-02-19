package aitool

import (
	"path/filepath"
	"strings"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
)

// ideNameFromPath extracts the IDE name from an extensions.json path.
// e.g. "/home/user/.vscode/extensions/extensions.json" → "VS Code"
var ideDirNames = map[string]string{
	".vscode":     "VS Code",
	".vscode-oss": "VSCodium",
	".cursor":     "Cursor",
	".windsurf":   "Windsurf",
}

const ideExtensionsApp = "ide_extensions"

type aiExtensionDiscoverer struct {
	config DiscoveryConfig
}

// NewAIExtensionDiscoverer creates a discoverer that bridges the VSIX extension reader
// to find AI-specific IDE extensions.
func NewAIExtensionDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &aiExtensionDiscoverer{config: config}, nil
}

func (d *aiExtensionDiscoverer) Name() string { return "AI IDE Extensions" }
func (d *aiExtensionDiscoverer) App() string { return ideExtensionsApp }

func (d *aiExtensionDiscoverer) EnumTools(handler AIToolHandlerFn) error {
	// IDE extensions are system-scoped; skip when system scope is not enabled
	if !d.config.ScopeEnabled(AIToolScopeSystem) {
		return nil
	}

	vsixReader, err := readers.NewVSIXExtReaderFromDefaultDistributions()
	if err != nil {
		logger.Debugf("No IDE extensions found: %v", err)
		return nil
	}

	return vsixReader.EnumManifests(func(manifest *models.PackageManifest, pr readers.PackageReader) error {
		return pr.EnumPackages(func(pkg *models.Package) error {
			info, ok := knownAIExtensions[strings.ToLower(pkg.Name)]
			if !ok {
				return nil
			}

			tool := &AITool{
				Name:       info.DisplayName,
				Type:       AIToolTypeAIExtension,
				Scope:      AIToolScopeSystem,
				App:       ideExtensionsApp,
				ConfigPath: manifest.GetPath(),
			}
			tool.ID = GenerateID(tool.App, string(tool.Type), string(tool.Scope), pkg.Name, tool.ConfigPath)
			tool.SourceID = GenerateSourceID(tool.App, tool.ConfigPath)
			tool.SetMeta("extension.id", pkg.Name)
			tool.SetMeta("extension.version", pkg.Version)
			tool.SetMeta("extension.ecosystem", manifest.Ecosystem)
			if ide := ideNameFromPath(manifest.GetPath()); ide != "" {
				tool.SetMeta("extension.ide", ide)
			}

			return handler(tool)
		})
	})
}

func ideNameFromPath(configPath string) string {
	// Walk up from extensions.json to find the IDE directory.
	// Path pattern: ~/.vscode/extensions/extensions.json
	dir := filepath.Dir(configPath) // .../extensions
	dir = filepath.Dir(dir)         // .../.vscode
	base := filepath.Base(dir)
	if name, ok := ideDirNames[base]; ok {
		return name
	}
	return ""
}
