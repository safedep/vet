// Package agent declares the building blocks for implement vet agent.
package agent

import (
	"context"

	"github.com/cloudwego/eino/components/tool"
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

// Session is a placeholder for session interface
type Session interface{}

type Agent interface {
	Execute(context.Context, Session, Input) (Output, error)
}

type ToolBuilder interface {
	Build(context.Context) ([]tool.BaseTool, error)
}
