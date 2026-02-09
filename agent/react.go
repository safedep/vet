package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	einoutils "github.com/cloudwego/eino/components/tool/utils"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/flow/agent/react"
	"github.com/cloudwego/eino/schema"
	"github.com/google/uuid"
)

type ReactQueryAgentConfig struct {
	MaxSteps        int
	SystemPrompt    string
	MessageRewriter func(ctx context.Context, messages []*schema.Message) []*schema.Message
}

type reactQueryAgent struct {
	config    ReactQueryAgentConfig
	model     model.ToolCallingChatModel
	tools     []tool.BaseTool
	id        string
	debugStep atomic.Uint64
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
		id:     uuid.New().String(),
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

	m := a.model
	if executionContext.OnThinking != nil {
		m = &thinkingAwareModel{inner: m, onThinking: executionContext.OnThinking}
	}

	agentConfig := &react.AgentConfig{
		ToolCallingModel: m,
		ToolsConfig: compose.ToolsNodeConfig{
			Tools: a.wrapToolsForError(a.tools),
			ToolArgumentsHandler: func(ctx context.Context, name string, arguments string) (string, error) {
				// Only allow introspection if the function is provided. Do not allow mutation.
				if executionContext.OnToolCall != nil {
					_ = executionContext.OnToolCall(ctx, session, input, name, arguments)
				}

				return arguments, nil
			},
		},
		MaxStep: a.config.MaxSteps,
	}

	if a.config.MessageRewriter != nil {
		agentConfig.MessageRewriter = a.config.MessageRewriter
	}

	if debugDir := os.Getenv("VET_AGENT_DEBUG_PROMPT_DIR"); debugDir != "" {
		agentConfig.MessageModifier = a.newDebugPromptDumper(debugDir)
	}

	agent, err := react.NewAgent(ctx, agentConfig)
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

func (a *reactQueryAgent) wrapToolsForError(tools []tool.BaseTool) []tool.BaseTool {
	wrappedTools := make([]tool.BaseTool, len(tools))

	for i, tool := range tools {
		wrappedTools[i] = einoutils.WrapToolWithErrorHandler(tool, func(_ context.Context, err error) string {
			errorMessage := map[string]string{
				"error":      err.Error(),
				"suggestion": "Tool call failed, Please try a different approach or check your input.",
			}

			encodedError, err := json.Marshal(errorMessage)
			if err != nil {
				return ""
			}

			return string(encodedError)
		})
	}

	return wrappedTools
}

// thinkingAwareModel wraps a ToolCallingChatModel and fires a callback
// when the model produces reasoning/thinking content.
type thinkingAwareModel struct {
	inner      model.ToolCallingChatModel
	onThinking func(ctx context.Context, content string) error
}

func (m *thinkingAwareModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	msg, err := m.inner.Generate(ctx, input, opts...)
	if err == nil && msg != nil && msg.ReasoningContent != "" && m.onThinking != nil {
		_ = m.onThinking(ctx, msg.ReasoningContent)
	}

	return msg, err
}

func (m *thinkingAwareModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return m.inner.Stream(ctx, input, opts...)
}

func (m *thinkingAwareModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	inner, err := m.inner.WithTools(tools)
	if err != nil {
		return nil, err
	}

	return &thinkingAwareModel{inner: inner, onThinking: m.onThinking}, nil
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
