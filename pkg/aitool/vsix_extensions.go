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

// enumVSIXExtensions iterates all extensions from r and calls handler for each
// accepted one. nameFor receives the lowercased extension id and returns the
// display name; returning ok=false skips the extension. The caller handles
// scope-gating and reader construction.
func enumVSIXExtensions(
	r vsixManifestReader,
	app string,
	toolType AIToolType,
	nameFor func(id string) (name string, ok bool),
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
