package tools

import (
	"context"
	"fmt"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/safedep/vet/mcp"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
)

type vetQueryTool struct {
	reader    readers.PackageManifestReader
	manifests map[string]*models.PackageManifest
}

var _ mcp.McpTool = &vetQueryTool{}

// Models for responding to LLM
type packageManifest struct {
	ID        string `json:"id"`
	Path      string `json:"path"`
	Ecosystem string `json:"ecosystem"`
}

type listPackageManifestsResponse struct {
	Manifests []packageManifest `json:"manifests"`
}

type packageInfo struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

type listPackagesResponse struct {
	Packages []packageInfo `json:"packages"`
}

// NewVetQueryTool creates a new vet query tool. The purpose of this tool
// is to provide agents access to vet data. The actual data may come from any
// reader or source.
func NewVetQueryTool(r readers.PackageManifestReader) (*vetQueryTool, error) {
	tool := &vetQueryTool{
		reader:    r,
		manifests: make(map[string]*models.PackageManifest),
	}

	err := tool.loadManifests()
	if err != nil {
		return nil, fmt.Errorf("failed to load manifests: %w", err)
	}

	return tool, nil
}

func (t *vetQueryTool) Register(server *server.MCPServer) error {
	listPackageManifestsTool := mcpgo.NewTool("vet_query_list_package_manifests",
		mcpgo.WithDescription("List all package manifests scanned by SafeDep vet software composition analysis tool"),
	)

	listPackagesTool := mcpgo.NewTool("vet_query_list_packages",
		mcpgo.WithDescription("List all packages identified within a package manifest"),
		mcpgo.WithString("manifest_id", mcpgo.Required(), mcpgo.Description("The ID of the package manifest to list packages for")),
	)

	server.AddTool(listPackageManifestsTool, t.executeListPackageManifests)
	server.AddTool(listPackagesTool, t.executeListPackages)

	return nil
}

func (t *vetQueryTool) executeListPackages(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	manifestID, err := req.RequireString("manifest_id")
	if err != nil {
		return nil, fmt.Errorf("manifest_id is required: %w", err)
	}

	manifest, ok := t.manifests[manifestID]
	if !ok {
		return nil, fmt.Errorf("manifest not found: %s", manifestID)
	}

	response := listPackagesResponse{
		Packages: make([]packageInfo, 0, len(manifest.GetPackages())),
	}

	for _, pkg := range manifest.GetPackages() {
		response.Packages = append(response.Packages, packageInfo{
			Ecosystem: pkg.GetSpecEcosystem().String(),
			Name:      pkg.GetName(),
			Version:   pkg.GetVersion(),
		})
	}

	serializedResponse, err := serializeForLlm(response)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize response: %w", err)
	}

	return mcpgo.NewToolResultText(serializedResponse), nil
}

func (t *vetQueryTool) executeListPackageManifests(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	response := listPackageManifestsResponse{
		Manifests: make([]packageManifest, 0, len(t.manifests)),
	}

	for manifestID, manifest := range t.manifests {
		response.Manifests = append(response.Manifests, packageManifest{
			ID:        manifestID,
			Path:      manifest.GetSource().GetDisplayPath(),
			Ecosystem: manifest.GetControlTowerSpecEcosystem().String(),
		})
	}

	serializedResponse, err := serializeForLlm(response)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize response: %w", err)
	}

	return mcpgo.NewToolResultText(serializedResponse), nil
}

func (t *vetQueryTool) loadManifests() error {
	index := 0
	err := t.reader.EnumManifests(func(manifest *models.PackageManifest, reader readers.PackageReader) error {
		manifestID := fmt.Sprintf("%d-%s-%s-%s", index, manifest.GetControlTowerSpecEcosystem().String(),
			manifest.GetSource().GetNamespace(), manifest.GetSource().GetPath())

		t.manifests[manifestID] = manifest

		index++
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to load manifests: %w", err)
	}

	return nil
}
