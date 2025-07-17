package server

import (
	"fmt"
	"os"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/insights/v2/insightsv2grpc"
	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	"github.com/safedep/dry/adapters"
	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/mcp"
	"github.com/safedep/vet/mcp/server"
	"github.com/safedep/vet/mcp/tools"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/spf13/cobra"
)

var (
	mcpServerSseServerAddr      string
	mcpServerServerType         string
	skipDefaultTools            bool
	registerVetSQLQueryTool     bool
	vetSQLQueryToolDBPath       string
	registerPackageRegistryTool bool
)

func newMcpServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start the MCP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := startMcpServer()
			if err != nil {
				logger.Errorf("Failed to start server: %v", err)
				os.Exit(1)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&mcpServerSseServerAddr, "sse-server-addr", "localhost:9988", "The address to listen for SSE connections")
	cmd.Flags().StringVar(&mcpServerServerType, "server-type", "stdio", "The type of server to start (stdio, sse)")

	// We allow skipping default tools to allow for custom tools to be registered when the server starts.
	// This is useful for agents to avoid unnecessary tool registration.
	cmd.Flags().BoolVar(&skipDefaultTools, "skip-default-tools", false, "Skip registering default tools")

	// Options to register sqlite3 query tool
	cmd.Flags().BoolVar(&registerVetSQLQueryTool, "sql-query-tool", false, "Register the vet report query by SQL tool (requires database path)")
	cmd.Flags().StringVar(&vetSQLQueryToolDBPath, "sql-query-tool-db-path", "", "The path to the vet SQLite3 database file")

	// Options to register package registry tool
	cmd.Flags().BoolVar(&registerPackageRegistryTool, "package-registry-tool", false, "Register the package registry tool")

	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if registerVetSQLQueryTool && vetSQLQueryToolDBPath == "" {
			return fmt.Errorf("database path is required for SQL query tool")
		}

		return nil
	}

	return cmd
}

func startMcpServer() error {
	driver, err := buildMcpDriver()
	if err != nil {
		return fmt.Errorf("failed to build MCP driver: %w", err)
	}

	var mcpSrv server.McpServer
	switch mcpServerServerType {
	case "stdio":
		mcpSrv, err = server.NewMcpServerWithStdioTransport(server.DefaultMcpServerConfig())
	case "sse":
		mcpSrv, err = server.NewMcpServerWithSseTransport(server.DefaultMcpServerConfig())
	default:
		return fmt.Errorf("invalid server type: %s", mcpServerServerType)
	}

	if err != nil {
		return fmt.Errorf("failed to create MCP server: %w", err)
	}

	if !skipDefaultTools {
		err = doRegisterDefaultTools(mcpSrv, driver)
		if err != nil {
			return fmt.Errorf("failed to register default tools: %w", err)
		}
	}

	if registerVetSQLQueryTool {
		err = doRegisterVetSQLQueryTool(mcpSrv)
		if err != nil {
			return fmt.Errorf("failed to register vet SQL query tool: %w", err)
		}
	}

	if registerPackageRegistryTool {
		err = doRegisterPackageRegistryTool(mcpSrv, driver)
		if err != nil {
			return fmt.Errorf("failed to register package registry tool: %w", err)
		}
	}

	err = mcpSrv.Start()
	if err != nil {
		return fmt.Errorf("failed to start MCP server: %w", err)
	}

	return nil
}

func doRegisterDefaultTools(mcpSrv server.McpServer, driver mcp.Driver) error {
	err := mcpSrv.RegisterTool(tools.NewPackageInsightsTool(driver))
	if err != nil {
		return fmt.Errorf("failed to register package insights tool: %w", err)
	}

	err = mcpSrv.RegisterTool(tools.NewPackageRegistryTool(driver))
	if err != nil {
		return fmt.Errorf("failed to register package registry tool: %w", err)
	}

	err = mcpSrv.RegisterTool(tools.NewPackageMalwareTool(driver))
	if err != nil {
		return fmt.Errorf("failed to register package malware tool: %w", err)
	}

	return nil
}

func doRegisterVetSQLQueryTool(mcpSrv server.McpServer) error {
	tool, err := tools.NewVetSQLQueryTool(vetSQLQueryToolDBPath)
	if err != nil {
		return fmt.Errorf("failed to create vet SQL query tool: %w", err)
	}

	return mcpSrv.RegisterTool(tool)
}

func doRegisterPackageRegistryTool(mcpSrv server.McpServer, driver mcp.Driver) error {
	err := mcpSrv.RegisterTool(tools.NewPackageRegistryTool(driver))
	if err != nil {
		return fmt.Errorf("failed to register package registry tool: %w", err)
	}

	return nil
}

func buildMcpDriver() (mcp.Driver, error) {
	insightsConn, err := auth.InsightsV2CommunityClientConnection("vet-mcp-insights")
	if err != nil {
		return nil, fmt.Errorf("failed to create insights client: %w", err)
	}

	communityConn, err := auth.MalwareAnalysisCommunityClientConnection("vet-mcp-malware")
	if err != nil {
		return nil, fmt.Errorf("failed to create community client: %w", err)
	}

	insightsClient := insightsv2grpc.NewInsightServiceClient(insightsConn)
	malysisClient := malysisv1grpc.NewMalwareAnalysisServiceClient(communityConn)

	githubAdapter, err := adapters.NewGithubClient(adapters.DefaultGitHubClientConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create github client: %w", err)
	}

	driver, err := mcp.NewDefaultDriver(insightsClient, malysisClient, githubAdapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create MCP driver: %w", err)
	}

	return driver, nil
}
