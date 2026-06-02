package aitool

import (
	"strings"

	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
)

// vsixManifestReader is the minimal interface needed by VSIX extension discoverers.
type vsixManifestReader interface {
	EnumManifests(func(*models.PackageManifest, readers.PackageReader) error) error
}

// extensionNameFn resolves a display name for a lowercased extension id.
// Returning ok=false skips the extension.
type extensionNameFn func(id string) (name string, ok bool)

// acceptAll accepts every extension, using the raw id as the display name.
func acceptAll(id string) (string, bool) { return id, true }

// enumVSIXExtensions iterates all extensions from r and calls handler for each
// accepted one. The caller handles scope-gating and reader construction.
func enumVSIXExtensions(
	r vsixManifestReader,
	app string,
	toolType AIToolType,
	nameFor extensionNameFn,
	handler AIToolHandlerFn,
) error {
	return r.EnumManifests(func(manifest *models.PackageManifest, pr readers.PackageReader) error {
		return pr.EnumPackages(func(pkg *models.Package) error {
			name, ok := nameFor(strings.ToLower(pkg.Name))
			if !ok {
				return nil
			}

			tool := &AITool{
				Name:       name,
				Type:       toolType,
				Scope:      AIToolScopeSystem,
				App:        app,
				AppDisplay: app,
				ConfigPath: manifest.GetPath(),
			}

			tool.ID = generateID(tool.App, string(tool.Type), string(tool.Scope), pkg.Name, tool.ConfigPath)
			tool.SourceID = generateSourceID(tool.App, tool.ConfigPath)
			tool.SetMeta("extension.id", pkg.Name)
			tool.SetMeta("extension.version", pkg.Version)
			tool.SetMeta("extension.ecosystem", manifest.Ecosystem)

			if ide := ideNameFromPath(manifest.GetPath()); ide != "" {
				tool.SetMeta("extension.ide", ide)
				tool.AppDisplay = ide
			}

			return handler(tool)
		})
	})
}
