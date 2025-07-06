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

type Agent interface {
	Execute(context.Context, Session, Input) (Output, error)
}

type ToolBuilder interface {
	Build(context.Context) ([]tool.BaseTool, error)
}
