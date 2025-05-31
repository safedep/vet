package tools

import (
	"context"
	"fmt"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/safedep/dry/api/pb"
	"github.com/safedep/vet/mcp"
	"github.com/safedep/vet/pkg/common/logger"
)

type packageRegistryTool struct {
	driver mcp.Driver
}

var _ mcp.McpTool = &packageRegistryTool{}

func NewPackageRegistryTool(driver mcp.Driver) *packageRegistryTool {
	return &packageRegistryTool{
		driver: driver,
	}
}

func (t *packageRegistryTool) Register(server *server.MCPServer) error {
	getPackageLatestVersionTool := mcpgo.NewTool("get_package_latest_version",
		mcpgo.WithDescription("Get the latest version of a package"),
		mcpgo.WithString("purl", mcpgo.Required(), mcpgo.Description("The package URL to get the latest version of")),
	)

	getPackageAvailableVersionsTool := mcpgo.NewTool("get_package_available_versions",
		mcpgo.WithDescription("Get all available versions of a package"),
		mcpgo.WithString("purl", mcpgo.Required(), mcpgo.Description("The package URL to get the available versions of")),
	)

	server.AddTool(getPackageLatestVersionTool, t.executeGetPackageLatestVersion)
	server.AddTool(getPackageAvailableVersionsTool, t.executeGetPackageAvailableVersions)

	return nil
}

func (t *packageRegistryTool) executeGetPackageLatestVersion(ctx context.Context,
	req mcpgo.CallToolRequest,
) (*mcpgo.CallToolResult, error) {
	purl, err := req.RequireString("purl")
	if err != nil {
		return nil, fmt.Errorf("purl is required: %w", err)
	}

	logger.Debugf("Getting latest version for package: %s", purl)

	parsedPurl, err := pb.NewPurlPackageVersion(purl)
	if err != nil {
		return nil, fmt.Errorf("invalid purl: %w", err)
	}

	latestVersion, err := t.driver.GetPackageLatestVersion(ctx, parsedPurl.PackageVersion().GetPackage())
	if err != nil {
		return nil, fmt.Errorf("failed to get package latest version: %w", err)
	}

	latestVersionJson, err := serializeForLlm(latestVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize latest version: %w", err)
	}

	return mcpgo.NewToolResultText(latestVersionJson), nil
}

func (t *packageRegistryTool) executeGetPackageAvailableVersions(ctx context.Context,
	req mcpgo.CallToolRequest,
) (*mcpgo.CallToolResult, error) {
	purl, err := req.RequireString("purl")
	if err != nil {
		return nil, fmt.Errorf("purl is required: %w", err)
	}

	logger.Debugf("Getting available versions for package: %s", purl)

	parsedPurl, err := pb.NewPurlPackageVersion(purl)
	if err != nil {
		return nil, fmt.Errorf("invalid purl: %w", err)
	}

	availableVersions, err := t.driver.GetPackageAvailableVersions(ctx, parsedPurl.PackageVersion().GetPackage())
	if err != nil {
		return nil, fmt.Errorf("failed to get package available versions: %w", err)
	}

	availableVersionsJson, err := serializeForLlm(availableVersions)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize available versions: %w", err)
	}

	return mcpgo.NewToolResultText(availableVersionsJson), nil
}
