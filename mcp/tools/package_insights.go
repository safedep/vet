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

// PackageInsightsTool provides security insights about packages
type packageInsightsTool struct {
	driver mcp.Driver
}

var _ mcp.McpTool = &packageInsightsTool{}

// NewPackageInsightsTool creates a new instance of PackageInsightsTool
func NewPackageInsightsTool(driver mcp.Driver) *packageInsightsTool {
	return &packageInsightsTool{
		driver: driver,
	}
}

// Register registers the tool with the MCP server
func (t *packageInsightsTool) Register(server *server.MCPServer) error {
	vulnerabilityTool := mcpgo.NewTool("get_package_version_vulnerabilities",
		mcpgo.WithDescription("Get vulnerabilities for a package version"),
		mcpgo.WithString("purl", mcpgo.Required(), mcpgo.Description("The package URL to get vulnerabilities for")),
	)

	popularityTool := mcpgo.NewTool("get_package_version_popularity",
		mcpgo.WithDescription("Get popularity for a package version"),
		mcpgo.WithString("purl", mcpgo.Required(), mcpgo.Description("The package URL to get popularity for")),
	)

	licenseInfoTool := mcpgo.NewTool("get_package_version_license_info",
		mcpgo.WithDescription("Get license info for a package version"),
		mcpgo.WithString("purl", mcpgo.Required(), mcpgo.Description("The package URL to get license info for")),
	)

	server.AddTool(vulnerabilityTool, t.executeGetPackageVulnerabilities)
	server.AddTool(popularityTool, t.executeGetPackagePopularity)
	server.AddTool(licenseInfoTool, t.executeGetPackageLicenseInfo)

	return nil
}

func (t *packageInsightsTool) executeGetPackageVulnerabilities(ctx context.Context,
	req mcpgo.CallToolRequest,
) (*mcpgo.CallToolResult, error) {
	purl, err := req.RequireString("purl")
	if err != nil {
		return nil, fmt.Errorf("purl is required: %w", err)
	}

	parsedPurl, err := pb.NewPurlPackageVersion(purl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse purl: %w", err)
	}

	logger.Debugf("Getting vulnerabilities for package: %s", purl)

	vulns, err := t.driver.GetPackageVersionVulnerabilities(ctx, parsedPurl.PackageVersion())
	if err != nil {
		return nil, fmt.Errorf("failed to get package vulnerabilities: %w", err)
	}

	logger.Debugf("Found %d vulnerabilities for package: %s", len(vulns), purl)

	vulnsJson, err := serializeForLlm(vulns)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize vulnerabilities: %w", err)
	}

	return mcpgo.NewToolResultText(vulnsJson), nil
}

func (t *packageInsightsTool) executeGetPackagePopularity(ctx context.Context,
	req mcpgo.CallToolRequest,
) (*mcpgo.CallToolResult, error) {
	purl, err := req.RequireString("purl")
	if err != nil {
		return nil, fmt.Errorf("purl is required: %w", err)
	}

	parsedPurl, err := pb.NewPurlPackageVersion(purl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse purl: %w", err)
	}

	logger.Debugf("Getting popularity for package: %s", purl)

	popularity, err := t.driver.GetPackageVersionPopularity(ctx, parsedPurl.PackageVersion())
	if err != nil {
		return nil, fmt.Errorf("failed to get package popularity: %w", err)
	}

	logger.Debugf("Found %d popularity for package: %s", len(popularity), purl)

	popularityJson, err := serializeForLlm(popularity)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize popularity: %w", err)
	}

	return mcpgo.NewToolResultText(popularityJson), nil
}

func (t *packageInsightsTool) executeGetPackageLicenseInfo(ctx context.Context,
	req mcpgo.CallToolRequest,
) (*mcpgo.CallToolResult, error) {
	purl, err := req.RequireString("purl")
	if err != nil {
		return nil, fmt.Errorf("purl is required: %w", err)
	}

	parsedPurl, err := pb.NewPurlPackageVersion(purl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse purl: %w", err)
	}

	logger.Debugf("Getting license info for package: %s", purl)

	licenseInfo, err := t.driver.GetPackageVersionLicenseInfo(ctx, parsedPurl.PackageVersion())
	if err != nil {
		return nil, fmt.Errorf("failed to get package license info: %w", err)
	}

	logger.Debugf("Found %d license info for package: %s", len(licenseInfo.Licenses), purl)

	licenseInfoJson, err := serializeForLlm(licenseInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize license info: %w", err)
	}

	return mcpgo.NewToolResultText(licenseInfoJson), nil
}
