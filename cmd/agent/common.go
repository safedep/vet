package agent

import (
	"context"
	"fmt"
	"os"

	"github.com/charmbracelet/glamour"

	"github.com/safedep/vet/agent"
)

func buildModelFromEnvironment() (*agent.Model, error) {
	model, err := agent.BuildModelFromEnvironment(fastMode)
	if err != nil {
		return nil, fmt.Errorf("failed to build LLM model adapter using environment configuration: %w", err)
	}

	return model, nil
}

func executeAgentPrompt(agentExecutor agent.Agent, session agent.Session, prompt string) error {
	output, err := agentExecutor.Execute(context.Background(), session, agent.Input{
		Query: prompt,
	}, agent.WithToolCallHook(func(ctx context.Context, session agent.Session, input agent.Input, toolName string, toolArgs string) error {
		os.Stderr.WriteString(fmt.Sprintf("Tool called: %s with args: %s\n", toolName, toolArgs))
		return nil
	}))
	if err != nil {
		return fmt.Errorf("failed to execute agent: %w", err)
	}

	terminalRenderer, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(80),
		glamour.WithEmoji(),
	)
	if err != nil {
		return fmt.Errorf("failed to create glamour renderer: %w", err)
	}

	rendered, err := terminalRenderer.Render(output.Answer)
	if err != nil {
		return fmt.Errorf("failed to render answer: %w", err)
	}

	_, err = os.Stdout.WriteString(rendered)
	if err != nil {
		return fmt.Errorf("failed to write answer: %w", err)
	}

	return nil
}
