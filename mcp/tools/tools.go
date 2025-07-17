package tools

import (
	"github.com/safedep/vet/mcp"
	"github.com/safedep/vet/mcp/server"
)

func RegisterAll(server server.McpServer, driver mcp.Driver) error {
	malwareTool := NewPackageMalwareTool(driver)
	insightsTool := NewPackageInsightsTool(driver)
	registryTool := NewPackageRegistryTool(driver)

	if err := server.RegisterTool(malwareTool); err != nil {
		return err
	}

	if err := server.RegisterTool(insightsTool); err != nil {
		return err
	}

	if err := server.RegisterTool(registryTool); err != nil {
		return err
	}

	return nil
}
