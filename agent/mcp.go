package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	einomcp "github.com/cloudwego/eino-ext/components/tool/mcp"
	"github.com/cloudwego/eino/components/tool"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

type McpClientToolBuilderConfig struct {
	// Common config
	ClientName    string
	ClientVersion string

	// SSE client config
	SseURL  string
	Headers map[string]string

	// Stdout client config
	SkipDefaultTools           bool
	SQLQueryToolEnabled        bool
	SQLQueryToolDBPath         string
	PackageRegistryToolEnabled bool

	// Enable debug mode for the MCP client.
	Debug bool
}

type mcpClientToolBuilder struct {
	config McpClientToolBuilderConfig
}

var _ ToolBuilder = (*mcpClientToolBuilder)(nil)

// NewMcpClientToolBuilder creates a new MCP client tool builder for `vet` MCP server.
// This basically connects to vet MCP server over SSE or executes the `vet server mcp` command
// to start a MCP server in stdio mode. We maintain loose coupling between the MCP client and the MCP server
// by allowing the client to be configured with a set of flags to enable/disable specific tools. We do this
// to ensure vet MCP contract is not violated and evolves independently. vet Agents will in turn depend on
// vet MCP server for data access.
func NewMcpClientToolBuilder(config McpClientToolBuilderConfig) (*mcpClientToolBuilder, error) {
	return &mcpClientToolBuilder{
		config: config,
	}, nil
}

func (b *mcpClientToolBuilder) Build(ctx context.Context) ([]tool.BaseTool, error) {
	var cli *client.Client
	var err error

	if b.config.SseURL != "" {
		cli, err = b.buildSseClient()
		if err != nil {
			return nil, fmt.Errorf("failed to create sse client: %w", err)
		}
	} else {
		cli, err = b.buildStdioClient()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdio client: %w", err)
		}
	}

	err = cli.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start mcp client: %w", err)
	}

	initRequest := mcp.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = mcp.Implementation{
		Name:    b.config.ClientName,
		Version: b.config.ClientVersion,
	}

	_, err = cli.Initialize(ctx, initRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize mcp client: %w", err)
	}

	tools, err := einomcp.GetTools(ctx, &einomcp.Config{
		Cli: cli,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get tools: %w", err)
	}

	return tools, nil
}

func (b *mcpClientToolBuilder) buildSseClient() (*client.Client, error) {
	cli, err := client.NewSSEMCPClient(b.config.SseURL, client.WithHeaders(b.config.Headers))
	if err != nil {
		return nil, fmt.Errorf("failed to create sse client: %w", err)
	}

	return cli, nil
}

// buildStdioClient is used to start vet mcp server with arguments
// based on the configuration.
func (b *mcpClientToolBuilder) buildStdioClient() (*client.Client, error) {
	binaryPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get running binary path: %w", err)
	}

	// vet-mcp server defaults to stdio transport. See cmd/server/mcp.go
	vetMcpServerCommandArgs := []string{"server", "mcp"}

	if b.config.Debug {
		vetMcpServerLogFile := filepath.Join(os.TempDir(), "vet-mcp-server.log")
		vetMcpServerCommandArgs = append(vetMcpServerCommandArgs, "-l", vetMcpServerLogFile)
	}

	if b.config.SQLQueryToolEnabled {
		vetMcpServerCommandArgs = append(vetMcpServerCommandArgs, "--sql-query-tool")
		vetMcpServerCommandArgs = append(vetMcpServerCommandArgs, "--sql-query-tool-db-path",
			b.config.SQLQueryToolDBPath)
	}

	if b.config.PackageRegistryToolEnabled {
		vetMcpServerCommandArgs = append(vetMcpServerCommandArgs, "--package-registry-tool")
	}

	if b.config.SkipDefaultTools {
		vetMcpServerCommandArgs = append(vetMcpServerCommandArgs, "--skip-default-tools")
	}

	environmentVariables := []string{}
	if b.config.Debug {
		environmentVariables = append(environmentVariables, "APP_LOG_LEVEL=debug")
	}

	cli, err := client.NewStdioMCPClient(binaryPath, environmentVariables, vetMcpServerCommandArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to create stdio client: %w", err)
	}

	return cli, nil
}
