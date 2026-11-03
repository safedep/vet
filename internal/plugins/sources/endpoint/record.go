package endpoint

import (
	"maps"
	"strings"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// toRecord maps an inventory item of the home directory of user to its
// report record. The record holds names only, never a secret value: the
// scanners keep the names of the environment variables and the headers,
// not their values.
func toRecord(it *inventory.Item, user *report.InventoryUser) report.InventoryItem {
	r := report.InventoryItem{
		Kind: kindOf(it), Type: typeOf(it.Kind), Name: it.Name, Path: it.ConfigPath, Client: it.App,
		Scope: scopeOf(it.Scope), Identity: it.ItemIdentity, Source: it.SourceID, User: user,
		Enabled: it.Enabled, Details: maps.Clone(it.Metadata),
	}
	if m := it.MCPServer; m != nil {
		r.MCPServer = &report.InventoryMCP{
			Transport: transportOf(m.Transport), Command: m.Command, Args: m.Args, URL: m.URL,
			EnvNames: m.EnvVarNames, HeaderNames: m.HeaderNames,
			AllowedTools: m.AllowedTools, AllowedResources: m.AllowedResources,
		}
	}
	if a := it.Agent; a != nil {
		r.Version = a.Version
		r.Agent = &report.InventoryAgent{
			PermissionMode: a.PermissionMode, Model: a.Model,
			InstructionFiles: a.InstructionFiles, APIKeyEnvName: a.APIKeyEnvName,
		}
	}
	if e := it.IDEExtension; e != nil {
		r.Extension = &report.InventoryExtension{IDE: e.IDE}
		if p := e.Package; p != nil {
			r.Version = p.Version
			r.Extension.Ecosystem = model.Ecosystem(p.Ecosystem)
			r.Extension.Package = p.Name
		}
	}
	if len(r.Details) == 0 {
		r.Details = nil
	}
	return r
}

func kindOf(it *inventory.Item) report.InventoryKind {
	switch it.Kind {
	case inventory.KindMCPServer:
		return report.InventoryMCPServer
	case inventory.KindAgentSkill:
		return report.InventorySkill
	case inventory.KindIDEExtension, inventory.KindBrowserExtension:
		return report.InventoryEditorPlugin
	}
	return report.InventoryAITool
}

var types = map[inventory.Kind]report.InventoryType{
	inventory.KindMCPServer:        report.InventoryTypeMCPServer,
	inventory.KindCodingAgent:      report.InventoryTypeCodingAgent,
	inventory.KindAIExtension:      report.InventoryTypeAIExtension,
	inventory.KindCLITool:          report.InventoryTypeCLITool,
	inventory.KindProjectConfig:    report.InventoryTypeProjectConfig,
	inventory.KindBrowserExtension: report.InventoryTypeBrowserExtension,
	inventory.KindIDEExtension:     report.InventoryTypeIDEExtension,
	inventory.KindAgentPlugin:      report.InventoryTypeAgentPlugin,
	inventory.KindAgentSkill:       report.InventoryTypeSkill,
}

func typeOf(k inventory.Kind) report.InventoryType { return types[k] }

func scopeOf(s inventory.Scope) string {
	if s == inventory.ScopeProject {
		return "project"
	}
	return "system"
}

func transportOf(t inventory.Transport) string {
	switch t {
	case inventory.TransportStdio:
		return "stdio"
	case inventory.TransportSSE:
		return "sse"
	case inventory.TransportStreamableHTTP:
		return "streamable_http"
	}
	return ""
}

// extensionManifest returns a one-package manifest for an IDE or AI
// extension that a marketplace serves, so the enrichers and the malware
// control check it as a package.
func extensionManifest(it *inventory.Item) *model.Manifest {
	e := it.IDEExtension
	if e == nil || e.Package == nil || e.Package.Name == "" || it.ConfigPath == "" {
		return nil
	}
	eco := model.Ecosystem(e.Package.Ecosystem)
	if !eco.Valid() {
		return nil
	}
	// The marketplace id, publisher.name, is the package name.
	id, err := model.NewPackageVersion(eco, strings.ToLower(e.Package.Name), e.Package.Version)
	if err != nil {
		return nil
	}
	return &model.Manifest{
		ID: model.ManifestID(it.ConfigPath, "endpoint/extensions"), Path: it.ConfigPath, Ecosystem: eco,
		Kind: model.ManifestKindEndpoint, Extractor: "endpoint/extensions",
		Packages: []*model.Package{{ID: id, Direct: true}},
	}
}

// mergeManifest adds the packages of m to the manifest of the same path.
// The IDE and the AI extension scanners can list one extension twice.
func mergeManifest(ms []*model.Manifest, m *model.Manifest) []*model.Manifest {
	for _, have := range ms {
		if have.ID != m.ID {
			continue
		}
		for _, p := range m.Packages {
			if !hasPackage(have, p.ID) {
				have.Packages = append(have.Packages, p)
			}
		}
		return ms
	}
	return append(ms, m)
}

func hasPackage(m *model.Manifest, id model.PackageVersion) bool {
	for _, p := range m.Packages {
		if p.ID.Equal(id) {
			return true
		}
	}
	return false
}
