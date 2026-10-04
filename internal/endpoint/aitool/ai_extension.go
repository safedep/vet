package aitool

import (
	"context"
	"path/filepath"

	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

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
	if !d.config.ScopeEnabled(inventory.ScopeSystem) {
		return nil
	}

	r := d.reader
	if r == nil {
		home, err := homeDirOf(d.config)
		if err != nil {
			log.Debugf("endpoint: no IDE extensions: %v", err)
			return nil
		}
		r = newVSIXReader(home)
	}

	return enumVSIXExtensions(r, ideExtensionsApp, inventory.KindAIExtension,
		func(id string) (string, bool) {
			info, ok := knownAIExtensions[id]
			return info.DisplayName, ok
		}, handler)
}

func ideNameFromPath(configPath string) string {
	extDir := filepath.Dir(configPath)               // .../extensions
	editorDir := filepath.Base(filepath.Dir(extDir)) // .vscode
	return editorDisplayName(editorDir)
}
