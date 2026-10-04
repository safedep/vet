package aitool

import (
	"strings"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

// enumVSIXExtensions calls handler for each accepted extension of r.
// nameFor gets the extension id in lower case and returns the display
// name. ok=false skips the extension.
func enumVSIXExtensions(
	r vsixManifestReader,
	app string,
	kind inventory.Kind,
	nameFor func(id string) (name string, ok bool),
	handler AIToolHandlerFn,
) error {
	manifests, err := r.Manifests()
	if err != nil {
		return err
	}
	for _, manifest := range manifests {
		for _, ext := range manifest.Extensions {
			name, ok := nameFor(strings.ToLower(ext.ID))
			if !ok {
				continue
			}
			ide := ideNameFromPath(manifest.Path)
			appDisplay := app
			if ide != "" {
				appDisplay = ide
			}
			// The identity keys off the extension id, not the display name.
			item := newItem(kind, inventory.ScopeSystem, app, appDisplay, ext.ID, manifest.Path)
			item.Name = name
			item.SetMeta(metaKeyExtensionID, ext.ID)
			item.SetMeta(metaKeyExtensionVersion, ext.Version)
			item.SetMeta(metaKeyExtensionEcosystem, string(manifest.Ecosystem))
			if ide != "" {
				item.SetMeta(metaKeyExtensionIDE, ide)
			}
			item.IDEExtension = &inventory.IDEExtensionDetail{
				Package: &inventory.PackageIdentity{
					Ecosystem: string(manifest.Ecosystem),
					Name:      ext.ID,
					Version:   ext.Version,
				},
				IDE: ide,
			}
			if err := handler(item); err != nil {
				return err
			}
		}
	}
	return nil
}
