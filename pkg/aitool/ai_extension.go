package aitool

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/readers"
)

// ideDirNames maps the base directory name of an IDE's extensions folder to its
// display name, e.g. "/home/user/.vscode/extensions/extensions.json" → "VS Code".
var ideDirNames = map[string]string{
	".vscode":      "VS Code",
	".vscode-oss":  "VSCodium",
	".cursor":      "Cursor",
	".windsurf":    "Windsurf",
	".antigravity": "Antigravity",
}

const (
	ideExtensionsApp        = "ide_extensions"
	ideExtensionsAppDisplay = "IDE Extensions"
)

type aiExtensionDiscoverer struct {
	config DiscoveryConfig
	// reader is injected in tests; nil means use the real default distributions.
	reader vsixManifestReader
}

func NewAIExtensionDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &aiExtensionDiscoverer{config: config}, nil
}

func (d *aiExtensionDiscoverer) Name() string { return "AI IDE Extensions" }
func (d *aiExtensionDiscoverer) App() string  { return ideExtensionsApp }

func (d *aiExtensionDiscoverer) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
	if !d.config.ScopeEnabled(AIToolScopeSystem) {
		return nil
	}

	r := d.reader
	if r == nil {
		var err error
		r, err = readers.NewVSIXExtReaderFromDefaultDistributions()
		if err != nil {
			logger.Debugf("No IDE extensions found: %v", err)
			return nil
		}
	}

	return enumVSIXExtensions(r, ideExtensionsApp, AIToolTypeAIExtension,
		func(id string) (string, bool) {
			info, ok := knownAIExtensions[strings.ToLower(id)]
			return info.DisplayName, ok
		}, handler)
}

func ideNameFromPath(configPath string) string {
	dir := filepath.Dir(configPath) // .../extensions
	dir = filepath.Dir(dir)         // .../.vscode
	base := filepath.Base(dir)

	if name, ok := ideDirNames[base]; ok {
		return name
	}

	return ""
}
