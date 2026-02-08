package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudwego/eino/schema"

	"github.com/safedep/vet/pkg/common/logger"
)

func (a *reactQueryAgent) newDebugPromptDumper(dir string) func(context.Context, []*schema.Message) []*schema.Message {
	return func(_ context.Context, messages []*schema.Message) []*schema.Message {
		step := a.debugStep.Add(1)
		filename := fmt.Sprintf("prompt-%s-%04d.md", a.id, step)
		path := filepath.Join(dir, filename)

		content := formatMessagesMarkdown(a.id, step, messages)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			logger.Warnf("[Agent Debug] Failed to write prompt dump to %s: %v", path, err)
		}

		return messages
	}
}

func formatMessagesMarkdown(agentID string, step uint64, messages []*schema.Message) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "# Agent Prompt - Step %d\n\n", step)
	fmt.Fprintf(&sb, "**Agent ID:** %s\n", agentID)
	fmt.Fprintf(&sb, "**Timestamp:** %s\n", time.Now().Format(time.RFC3339))

	for i, msg := range messages {
		sb.WriteString("\n---\n\n")

		role := string(msg.Role)
		annotation := ""
		if len(msg.ToolCalls) > 0 {
			annotation = " (tool_calls)"
		}
		if msg.ToolCallID != "" {
			toolName := msg.ToolName
			if toolName == "" {
				toolName = "unknown"
			}
			annotation = fmt.Sprintf(" [tool: %s] (call_id: %s)", toolName, msg.ToolCallID)
		}

		fmt.Fprintf(&sb, "## Message %d [%s]%s\n\n", i+1, role, annotation)

		content := msg.Content
		if len(msg.MultiContent) > 0 {
			var parts []string
			for _, part := range msg.MultiContent {
				parts = append(parts, part.Text)
			}
			content = strings.Join(parts, "\n")
		}

		if content != "" {
			sb.WriteString(content)
			sb.WriteString("\n")
		}

		if len(msg.ToolCalls) > 0 {
			sb.WriteString("\n### Tool Calls\n\n")
			for _, tc := range msg.ToolCalls {
				fmt.Fprintf(&sb, "- **%s**: %s(`%s`)\n", tc.ID, tc.Function.Name, tc.Function.Arguments)
			}
		}
	}

	return sb.String()
}
