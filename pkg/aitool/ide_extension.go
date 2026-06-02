package aitool

import (
	"context"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/readers"
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
	if !d.config.ScopeEnabled(AIToolScopeSystem) {
		return nil
	}

	r := d.reader
	if r == nil {
		var err error
		r, err = readers.NewVSIXExtReaderFromDefaultDistributions()
		if err != nil {
			logger.Debugf("IDE extensions unavailable: %v", err)
			return nil
		}
	}

	return enumVSIXExtensions(r, ideExtensionApp, AIToolTypeIDEExtension, acceptAll, handler)
}
