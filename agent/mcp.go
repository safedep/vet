package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cloudwego/eino/components/tool"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"

	einomcp "github.com/cloudwego/eino-ext/components/tool/mcp"
)

type McpClientToolBuilderConfig struct {
	SseURL        string
	Headers       map[string]string
	ClientName    string
	ClientVersion string

	// Config for start vet mcp server
	SkipDefaultTools    bool
	SQLQueryToolEnabled bool
	SQLQueryToolDBPath  string
}

type mcpClientToolBuilder struct {
	config McpClientToolBuilderConfig
}

var _ ToolBuilder = (*mcpClientToolBuilder)(nil)

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

func (b *mcpClientToolBuilder) buildStdioClient() (*client.Client, error) {
	binaryPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get running binary path: %w", err)
	}

	// TODO: We should not log by default. This is only for debugging purposes.
	vetMcpServerLogFile := filepath.Join(os.TempDir(), "vet-mcp-server.log")

	// vet-mcp server defaults to stdio transport. See cmd/server/mcp.go
	vetMcpServerCommandArgs := []string{"server", "mcp", "-l", vetMcpServerLogFile}

	if b.config.SQLQueryToolEnabled {
		vetMcpServerCommandArgs = append(vetMcpServerCommandArgs, "--sql-query-tool")
		vetMcpServerCommandArgs = append(vetMcpServerCommandArgs, "--sql-query-tool-db-path", b.config.SQLQueryToolDBPath)
	}

	if b.config.SkipDefaultTools {
		vetMcpServerCommandArgs = append(vetMcpServerCommandArgs, "--skip-default-tools")
	}

	cli, err := client.NewStdioMCPClient(binaryPath, []string{
		"APP_LOG_LEVEL=debug",
	}, vetMcpServerCommandArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to create stdio client: %w", err)
	}

	return cli, nil
}
