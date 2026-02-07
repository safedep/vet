package agent

import (
	_ "embed"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/agent"
	"github.com/safedep/vet/internal/analytics"
	"github.com/safedep/vet/pkg/clawhub"
	"github.com/safedep/vet/pkg/common/logger"
)

//go:embed clawhub_scanner_prompt.md
var clawHubScannerSystemPrompt string

var (
	clawHubSkillSlug   string
	clawHubInteractive bool
)

func newClawHubScannerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clawhub-scanner",
		Short: "Analyze a ClawHub skill for security issues using AI",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeClawHubScanner()
			if err != nil {
				logger.Errorf("failed to execute clawhub scanner: %v", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&clawHubSkillSlug, "skill", "", "ClawHub skill slug to analyze")
	cmd.Flags().BoolVar(&clawHubInteractive, "interactive", false, "Start interactive TUI mode")

	_ = cmd.MarkFlagRequired("skill")

	return cmd
}

func executeClawHubScanner() error {
	analytics.TrackAgentClawHubScanner()

	client := clawhub.NewClient()
	tools, cleanup := clawhub.NewSkillTools(client)
	defer cleanup()

	model, err := buildModelFromEnvironment()
	if err != nil {
		return fmt.Errorf("failed to build LLM model adapter using environment configuration: %w", err)
	}

	agentConfig := agent.ReactQueryAgentConfig{
		MaxSteps:     maxAgentSteps,
		SystemPrompt: clawHubScannerSystemPrompt,
	}

	if compactContext {
		compactorConfig := agent.DefaultToolContentCompactorConfig()
		compactorConfig.ToolNames = []string{"clawhub_read_skill_file"}
		agentConfig.MessageRewriter = agent.NewToolContentCompactor(compactorConfig)
	}

	agentExecutor, err := agent.NewReactQueryAgent(model.Client, agentConfig, agent.WithTools(tools))
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

	if clawHubInteractive {
		uiConfig := agent.DefaultAgentUIConfig()
		uiConfig.TitleText = "ClawHub Skill Scanner"
		uiConfig.TextInputPlaceholder = "Ask about the skill's security..."
		uiConfig.InitialSystemMessage = fmt.Sprintf("ClawHub Scanner initialized. Analyzing skill: %s...", clawHubSkillSlug)
		uiConfig.ModelName = model.Name
		uiConfig.ModelVendor = model.Vendor
		uiConfig.ModelFast = model.Fast

		return agent.StartUIWithConfig(agentExecutor, session, uiConfig)
	}

	prompt := singlePrompt
	if prompt == "" {
		prompt = fmt.Sprintf("Analyze the ClawHub skill '%s' for security issues.", clawHubSkillSlug)
	}

	return executeAgentPrompt(agentExecutor, session, prompt)
}
