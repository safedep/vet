package agent

import (
	"context"
	"fmt"

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
	cli, err := client.NewSSEMCPClient(b.config.SseURL, client.WithHeaders(b.config.Headers))
	if err != nil {
		return nil, fmt.Errorf("failed to create sse client: %w", err)
	}

	err = cli.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start sse client: %w", err)
	}

	initRequest := mcp.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = mcp.Implementation{
		Name:    b.config.ClientName,
		Version: b.config.ClientVersion,
	}

	_, err = cli.Initialize(ctx, initRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize sse client: %w", err)
	}

	tools, err := einomcp.GetTools(ctx, &einomcp.Config{
		Cli: cli,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get tools: %w", err)
	}

	return tools, nil
}
