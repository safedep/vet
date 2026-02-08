// Package agent declares the building blocks for implement vet agent.
package agent

import (
	"context"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

type Input struct {
	Query string
}

type AnswerFormat string

const (
	AnswerFormatMarkdown AnswerFormat = "markdown"
	AnswerFormatJSON     AnswerFormat = "json"
)

type Output struct {
	Answer string
	Format AnswerFormat
}

type Memory interface {
	AddInteraction(ctx context.Context, interaction *schema.Message) error
	GetInteractions(ctx context.Context) ([]*schema.Message, error)
	Clear(ctx context.Context) error
}

type Session interface {
	ID() string
	Memory() Memory
}

// AgentExecutionContext is to pass additional context to the agent
// on a per execution basis. This is required so that an agent can be configured
// and shared with different components while allowing the component to pass
// additional context to the agent.
type AgentExecutionContext struct {
	// OnToolCall is called when the agent is about to call a tool.
	// This is used for introspection only and not to mutate the agent's behavior.
	OnToolCall func(context.Context, Session, Input, string, string) error

	// OnThinking is called when the model produces reasoning/thinking content.
	// This is used for introspection only and not to mutate the agent's behavior.
	OnThinking func(ctx context.Context, content string) error
}

type AgentExecutionContextOpt func(*AgentExecutionContext)

func WithToolCallHook(fn func(context.Context, Session, Input, string, string) error) AgentExecutionContextOpt {
	return func(a *AgentExecutionContext) {
		a.OnToolCall = fn
	}
}

func WithThinkingHook(fn func(ctx context.Context, content string) error) AgentExecutionContextOpt {
	return func(a *AgentExecutionContext) {
		a.OnThinking = fn
	}
}

type Agent interface {
	// Execute executes the agent with the given input and returns the output.
	// Internally the agent may perform a multi-step operation based on config,
	// instructions and available tools.
	Execute(context.Context, Session, Input, ...AgentExecutionContextOpt) (Output, error)
}

// AgentToolCallIntrospectionFn is a function that introspects a tool call.
// This is aligned with eino contract.
type AgentToolCallIntrospectionFn func(context.Context /* name */, string /* args */, string) ( /* args */ string, error)

type ToolBuilder interface {
	Build(context.Context) ([]tool.BaseTool, error)
}
