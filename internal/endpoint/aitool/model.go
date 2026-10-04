package aitool

import "github.com/safedep/vet/v2/internal/endpoint/inventory"

const (
	metaKeyAppDisplay         = "app.display"
	metaKeyBinaryPath         = "binary.path"
	metaKeyBinaryVersion      = "binary.version"
	metaKeyBinaryVerified     = "binary.verified"
	metaKeyExtensionID        = "extension.id"
	metaKeyExtensionVersion   = "extension.version"
	metaKeyExtensionEcosystem = "extension.ecosystem"
	metaKeyExtensionIDE       = "extension.ide"
)

// newItem makes an item with its identity, its source id and the display
// name of its app. All the items of one config file share a source id.
func newItem(kind inventory.Kind, scope inventory.Scope, app, appDisplay, name, configPath string) *inventory.Item {
	it := &inventory.Item{
		Kind:         kind,
		ItemIdentity: inventory.ItemIdentity(app, kind, scope, name, configPath),
		SourceID:     inventory.SourceID(app, configPath),
		Name:         name,
		App:          app,
		Scope:        scope,
		ConfigPath:   configPath,
	}
	if appDisplay != "" {
		it.SetMeta(metaKeyAppDisplay, appDisplay)
	}
	return it
}
