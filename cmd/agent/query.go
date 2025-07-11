package agent

import (
	"context"
	"fmt"

	"github.com/safedep/vet/agent"
	"github.com/safedep/vet/internal/analytics"
	"github.com/safedep/vet/internal/command"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/spf13/cobra"

	_ "embed"
)

//go:embed query_prompt.md
var querySystemPrompt string

var queryAgentDBPath string

func newQueryAgentCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query agent allows analysis and querying the vet sqlite3 report database",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeQueryAgent()
			if err != nil {
				logger.Errorf("failed to execute query agent: %v", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&queryAgentDBPath, "db", "", "The path to the vet sqlite3 report database")

	_ = cmd.MarkFlagRequired("db")

	return cmd
}

func executeQueryAgent() error {
	analytics.TrackAgentQuery()

	toolBuilder, err := agent.NewMcpClientToolBuilder(agent.McpClientToolBuilderConfig{
		ClientName:          "vet-query-agent",
		ClientVersion:       command.GetVersion(),
		SkipDefaultTools:    true,
		SQLQueryToolEnabled: true,
		SQLQueryToolDBPath:  queryAgentDBPath,
	})
	if err != nil {
		return fmt.Errorf("failed to create MCP client tool builder: %w", err)
	}

	tools, err := toolBuilder.Build(context.Background())
	if err != nil {
		return fmt.Errorf("failed to build tools: %w", err)
	}

	model, err := buildModelFromEnvironment()
	if err != nil {
		return fmt.Errorf("failed to build LLM model adapter using environment configuration: %w", err)
	}

	agentExecutor, err := agent.NewReactQueryAgent(model.Client, agent.ReactQueryAgentConfig{
		MaxSteps:     maxAgentSteps,
		SystemPrompt: querySystemPrompt,
	}, agent.WithTools(tools))
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	memory, err := agent.NewSimpleMemory()
	if err != nil {
		return fmt.Errorf("failed to create memory: %w", err)
	}

	session, err := agent.NewSession(memory)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	if singlePrompt != "" {
		err = executeAgentPrompt(agentExecutor, session, singlePrompt)
		if err != nil {
			return fmt.Errorf("failed to execute agent prompt: %w", err)
		}
	} else {

		uiConfig := agent.DefaultAgentUIConfig()
		uiConfig.TitleText = "🔍 Query Agent - Interactive Query Mode"
		uiConfig.TextInputPlaceholder = "Ask me anything about your scan data..."
		uiConfig.InitialSystemMessage = "🤖 Query Agent initialized. Ask me anything about your dependencies, vulnerabilities and other supply chain risks."
		uiConfig.ModelName = model.Name
		uiConfig.ModelVendor = model.Vendor
		uiConfig.ModelFast = model.Fast

		err = agent.StartUIWithConfig(agentExecutor, session, uiConfig)
		if err != nil {
			return fmt.Errorf("failed to start agent interaction UI: %w", err)
		}
	}

	return nil
}
