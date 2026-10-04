package aitool

import (
	"context"

	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

// ideExtensionApp is intentionally singular ("ide_extension"), distinct from
// ideExtensionsApp ("ide_extensions") used by the AI-extension discoverer.
// Different app ids produce different item_identity hashes, keeping the
// IDE-extension and AI-extension facets separate in the endpoint catalog.
const ideExtensionApp = "ide_extension"

type ideExtensionDiscoverer struct {
	config DiscoveryConfig
	// reader is injected in tests; nil means use the real default distributions.
	reader vsixManifestReader
}

func NewIDEExtensionDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	return &ideExtensionDiscoverer{config: config}, nil
}

func (d *ideExtensionDiscoverer) Name() string { return "IDE Extensions" }
func (d *ideExtensionDiscoverer) App() string  { return ideExtensionApp }

func (d *ideExtensionDiscoverer) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
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

	return enumVSIXExtensions(r, ideExtensionApp, inventory.KindIDEExtension,
		func(id string) (string, bool) { return id, true }, handler)
}
