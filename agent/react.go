package agent

import (
	"context"
	"fmt"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/flow/agent/react"
	"github.com/cloudwego/eino/schema"
)

type ReactQueryAgentConfig struct {
	MaxSteps     int
	SystemPrompt string
}

type reactQueryAgent struct {
	config ReactQueryAgentConfig
	model  model.ToolCallingChatModel
	tools  []tool.BaseTool
}

var _ Agent = (*reactQueryAgent)(nil)

type reactQueryAgentOpt func(*reactQueryAgent)

func WithTools(tools []tool.BaseTool) reactQueryAgentOpt {
	return func(a *reactQueryAgent) {
		a.tools = tools
	}
}

func NewReactQueryAgent(model model.ToolCallingChatModel,
	config ReactQueryAgentConfig, opts ...reactQueryAgentOpt,
) (*reactQueryAgent, error) {
	a := &reactQueryAgent{
		config: config,
		model:  model,
	}

	for _, opt := range opts {
		opt(a)
	}

	if a.config.MaxSteps == 0 {
		a.config.MaxSteps = 30
	}

	return a, nil
}

func (a *reactQueryAgent) Execute(ctx context.Context, session Session, input Input, opts ...AgentExecutionContextOpt) (Output, error) {
	executionContext := &AgentExecutionContext{}
	for _, opt := range opts {
		opt(executionContext)
	}

	agent, err := react.NewAgent(ctx, &react.AgentConfig{
		ToolCallingModel: a.model,
		ToolsConfig: compose.ToolsNodeConfig{
			Tools: a.tools,
			ToolArgumentsHandler: func(ctx context.Context, name string, arguments string) (string, error) {
				// Only allow introspection if the function is provided. Do not allow mutation.
				if executionContext.OnToolCall != nil {
					_ = executionContext.OnToolCall(ctx, session, input, name, arguments)
				}

				return arguments, nil
			},
		},
		MaxStep: a.config.MaxSteps,
	})
	if err != nil {
		return Output{}, fmt.Errorf("failed to create react agent: %w", err)
	}

	var messages []*schema.Message

	// Start with the system prompt if available
	if a.config.SystemPrompt != "" {
		messages = append(messages, &schema.Message{
			Role:    schema.System,
			Content: a.config.SystemPrompt,
		})
	}

	// Add the previous interactions to the messages
	interactions, err := session.Memory().GetInteractions(ctx)
	if err != nil {
		return Output{}, fmt.Errorf("failed to get session memory: %w", err)
	}

	// TODO: Add a limit to the number of interactions to avoid context bloat
	messages = append(messages, interactions...)

	// Add the current user query message to the messages
	userQueryMsg := &schema.Message{
		Role:    schema.User,
		Content: input.Query,
	}

	messages = append(messages, userQueryMsg)

	// Execute the agent to produce a response
	msg, err := agent.Generate(ctx, messages)
	if err != nil {
		return Output{}, fmt.Errorf("failed to generate response: %w", err)
	}

	// Add the user query message to the session memory
	err = session.Memory().AddInteraction(ctx, userQueryMsg)
	if err != nil {
		return Output{}, fmt.Errorf("failed to add user query message to session memory: %w", err)
	}

	// Add the agent response message to the session memory
	err = session.Memory().AddInteraction(ctx, msg)
	if err != nil {
		return Output{}, fmt.Errorf("failed to add response message to session memory: %w", err)
	}

	return Output{
		Answer: a.schemaContent(msg),
	}, nil
}

func (a *reactQueryAgent) schemaContent(msg *schema.Message) string {
	content := msg.Content

	if len(msg.MultiContent) > 0 {
		content = ""
		for _, part := range msg.MultiContent {
			content += part.Text + "\n"
		}
	}

	return content
}
