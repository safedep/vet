package agent

import (
	"context"

	"github.com/cloudwego/eino/schema"
)

const (
	defaultCompactMessage              = "[Content compacted — call the tool again to re-read this file]"
	defaultMinContentSizeForCompaction = 50 * 1024
)

// ToolContentCompactorConfig configures the behavior of NewToolContentCompactor.
type ToolContentCompactorConfig struct {
	// ToolNames is the list of tool names whose results should be compacted.
	ToolNames []string
	// MinContentSize is the minimum content length (in bytes) for a tool result
	// to be eligible for compaction. Results shorter than this are left as-is.
	// Default: 0 (compact all matching results regardless of size).
	MinContentSize int
	// CompactMessage is the replacement content for compacted tool results.
	// If empty, a default message is used.
	CompactMessage string
}

// DefaultToolContentCompactorConfig returns a baseline config with sensible defaults.
// Callers should set ToolNames for their specific agent.
func DefaultToolContentCompactorConfig() ToolContentCompactorConfig {
	return ToolContentCompactorConfig{
		CompactMessage: defaultCompactMessage,
		MinContentSize: defaultMinContentSizeForCompaction,
	}
}

// NewToolContentCompactor returns a MessageRewriter that compacts tool result
// content for the specified tool names. It preserves the most recent tool result
// for each tool name and replaces earlier results with a compact placeholder,
// reducing context window usage when tools are called repeatedly.
func NewToolContentCompactor(config ToolContentCompactorConfig) func(context.Context, []*schema.Message) []*schema.Message {
	nameSet := make(map[string]bool, len(config.ToolNames))
	for _, name := range config.ToolNames {
		nameSet[name] = true
	}

	compactMsg := config.CompactMessage
	if compactMsg == "" {
		compactMsg = defaultCompactMessage
	}

	return func(_ context.Context, messages []*schema.Message) []*schema.Message {
		// Find the last tool result message index for each target tool name.
		// Tool messages use ToolCallID to correlate with the assistant's ToolCalls.
		// We identify matching tool messages by their ToolName field.
		lastIndex := make(map[string]int)
		for i, msg := range messages {
			if msg.Role != schema.Tool {
				continue
			}

			if _, ok := nameSet[msg.ToolName]; ok {
				lastIndex[msg.ToolName] = i
			}
		}

		if len(lastIndex) == 0 {
			return messages
		}

		// Compact earlier tool results, preserving the last one per tool name.
		for i, msg := range messages {
			if msg.Role != schema.Tool {
				continue
			}

			if _, ok := nameSet[msg.ToolName]; !ok {
				continue
			}

			if i < lastIndex[msg.ToolName] {
				if config.MinContentSize > 0 && len(msg.Content) < config.MinContentSize {
					continue
				}

				msg.Content = compactMsg
			}
		}

		return messages
	}
}
