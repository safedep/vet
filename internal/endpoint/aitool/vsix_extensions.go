package aitool

import "strings"

// enumVSIXExtensions calls handler for each accepted extension of r.
// nameFor gets the extension id in lower case and returns the display
// name. ok=false skips the extension.
func enumVSIXExtensions(
	r vsixManifestReader,
	app string,
	toolType AIToolType,
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
			tool := &AITool{
				Name:       name,
				Type:       toolType,
				Scope:      AIToolScopeSystem,
				App:        app,
				AppDisplay: app,
				ConfigPath: manifest.Path,
			}
			tool.ID = generateID(tool.App, string(tool.Type), string(tool.Scope), ext.ID, tool.ConfigPath)
			tool.SourceID = generateSourceID(tool.App, tool.ConfigPath)
			tool.SetMeta("extension.id", ext.ID)
			tool.SetMeta("extension.version", ext.Version)
			tool.SetMeta("extension.ecosystem", string(manifest.Ecosystem))
			ide := ideNameFromPath(manifest.Path)
			if ide != "" {
				tool.SetMeta("extension.ide", ide)
				tool.AppDisplay = ide
			}
			tool.Extension = &ExtensionConfig{ID: ext.ID, Version: ext.Version, Ecosystem: string(manifest.Ecosystem), IDE: ide}
			if err := handler(tool); err != nil {
				return err
			}
		}
	}
	return nil
}
