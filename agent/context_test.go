package agent

import (
	"context"
	"testing"

	"github.com/cloudwego/eino/schema"
	"github.com/stretchr/testify/assert"
)

const compactedPlaceholder = "[Content compacted — call the tool again to re-read this file]"

func TestNewToolContentCompactor(t *testing.T) {
	tests := []struct {
		name        string
		config      ToolContentCompactorConfig
		messages    []*schema.Message
		wantContent map[int]string
	}{
		{
			name: "compacts earlier tool results and preserves the last",
			config: ToolContentCompactorConfig{
				ToolNames: []string{"clawhub_read_skill_file"},
			},
			messages: []*schema.Message{
				{Role: schema.User, Content: "Analyze the skill"},
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_1", Function: schema.FunctionCall{Name: "clawhub_read_skill_file", Arguments: `{"path":"file1.py"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_1", ToolName: "clawhub_read_skill_file", Content: "def hello():\n    print('hello world')\n"},
				{Role: schema.Assistant, Content: "file1.py looks safe"},
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_2", Function: schema.FunctionCall{Name: "clawhub_read_skill_file", Arguments: `{"path":"file2.py"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_2", ToolName: "clawhub_read_skill_file", Content: "def suspicious():\n    return 'flagged'\n"},
			},
			wantContent: map[int]string{
				2: compactedPlaceholder,                        // first tool result compacted
				3: "file1.py looks safe",                       // assistant untouched
				5: "def suspicious():\n    return 'flagged'\n", // last tool result preserved
			},
		},
		{
			name: "preserves non-target tool results",
			config: ToolContentCompactorConfig{
				ToolNames: []string{"clawhub_read_skill_file"},
			},
			messages: []*schema.Message{
				{Role: schema.User, Content: "Analyze the skill"},
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_1", Function: schema.FunctionCall{Name: "clawhub_list_skill_files", Arguments: `{"slug":"test"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_1", ToolName: "clawhub_list_skill_files", Content: "file1.py\nfile2.py"},
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_2", Function: schema.FunctionCall{Name: "clawhub_read_skill_file", Arguments: `{"path":"file1.py"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_2", ToolName: "clawhub_read_skill_file", Content: "print('hello')"},
			},
			wantContent: map[int]string{
				2: "file1.py\nfile2.py", // non-target tool untouched
				4: "print('hello')",     // only match, so preserved
			},
		},
		{
			name: "no matching tools returns messages unchanged",
			config: ToolContentCompactorConfig{
				ToolNames: []string{"clawhub_read_skill_file"},
			},
			messages: []*schema.Message{
				{Role: schema.User, Content: "Hello"},
				{Role: schema.Assistant, Content: "Hi there"},
			},
			wantContent: map[int]string{
				0: "Hello",
				1: "Hi there",
			},
		},
		{
			name: "empty messages",
			config: ToolContentCompactorConfig{
				ToolNames: []string{"clawhub_read_skill_file"},
			},
			messages:    []*schema.Message{},
			wantContent: map[int]string{},
		},
		{
			name: "single tool result is preserved",
			config: ToolContentCompactorConfig{
				ToolNames: []string{"clawhub_read_skill_file"},
			},
			messages: []*schema.Message{
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_1", Function: schema.FunctionCall{Name: "clawhub_read_skill_file", Arguments: `{"path":"file1.py"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_1", ToolName: "clawhub_read_skill_file", Content: "print('hello')"},
			},
			wantContent: map[int]string{
				1: "print('hello')",
			},
		},
		{
			name: "multiple tool names tracked independently",
			config: ToolContentCompactorConfig{
				ToolNames: []string{"read_file", "fetch_url"},
			},
			messages: []*schema.Message{
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_1", Function: schema.FunctionCall{Name: "read_file", Arguments: `{"path":"a.txt"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_1", ToolName: "read_file", Content: "content of a.txt"},
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_2", Function: schema.FunctionCall{Name: "fetch_url", Arguments: `{"url":"http://example.com"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_2", ToolName: "fetch_url", Content: "page content"},
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_3", Function: schema.FunctionCall{Name: "read_file", Arguments: `{"path":"b.txt"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_3", ToolName: "read_file", Content: "content of b.txt"},
			},
			wantContent: map[int]string{
				1: compactedPlaceholder, // first read_file compacted
				3: "page content",       // fetch_url only call, preserved
				5: "content of b.txt",   // last read_file preserved
			},
		},
		{
			name: "three calls to same tool compacts first two",
			config: ToolContentCompactorConfig{
				ToolNames: []string{"clawhub_read_skill_file"},
			},
			messages: []*schema.Message{
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_1", Function: schema.FunctionCall{Name: "clawhub_read_skill_file", Arguments: `{"path":"a.py"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_1", ToolName: "clawhub_read_skill_file", Content: "aaa"},
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_2", Function: schema.FunctionCall{Name: "clawhub_read_skill_file", Arguments: `{"path":"b.py"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_2", ToolName: "clawhub_read_skill_file", Content: "bbb"},
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_3", Function: schema.FunctionCall{Name: "clawhub_read_skill_file", Arguments: `{"path":"c.py"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_3", ToolName: "clawhub_read_skill_file", Content: "ccc"},
			},
			wantContent: map[int]string{
				1: compactedPlaceholder, // first compacted
				3: compactedPlaceholder, // second compacted
				5: "ccc",                // last preserved
			},
		},
		{
			name: "MinContentSize skips short content",
			config: ToolContentCompactorConfig{
				ToolNames:      []string{"read_file"},
				MinContentSize: 10,
			},
			messages: []*schema.Message{
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_1", Function: schema.FunctionCall{Name: "read_file", Arguments: `{"path":"short.txt"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_1", ToolName: "read_file", Content: "tiny"},
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_2", Function: schema.FunctionCall{Name: "read_file", Arguments: `{"path":"long.txt"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_2", ToolName: "read_file", Content: "this is a much longer content string"},
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_3", Function: schema.FunctionCall{Name: "read_file", Arguments: `{"path":"latest.txt"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_3", ToolName: "read_file", Content: "latest content here"},
			},
			wantContent: map[int]string{
				1: "tiny",                // below MinContentSize, not compacted
				3: compactedPlaceholder,  // above MinContentSize, compacted
				5: "latest content here", // last result, preserved
			},
		},
		{
			name: "custom CompactMessage override",
			config: ToolContentCompactorConfig{
				ToolNames:      []string{"read_file"},
				CompactMessage: "[redacted]",
			},
			messages: []*schema.Message{
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_1", Function: schema.FunctionCall{Name: "read_file", Arguments: `{"path":"a.txt"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_1", ToolName: "read_file", Content: "first content"},
				{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
					{ID: "call_2", Function: schema.FunctionCall{Name: "read_file", Arguments: `{"path":"b.txt"}`}},
				}},
				{Role: schema.Tool, ToolCallID: "call_2", ToolName: "read_file", Content: "second content"},
			},
			wantContent: map[int]string{
				1: "[redacted]",     // custom message used
				3: "second content", // last preserved
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compactor := NewToolContentCompactor(tt.config)
			result := compactor(context.Background(), tt.messages)

			assert.Len(t, result, len(tt.messages))
			for idx, want := range tt.wantContent {
				assert.Equalf(t, want, result[idx].Content, "message[%d].Content", idx)
			}
		})
	}
}

func TestDefaultToolContentCompactorConfig(t *testing.T) {
	config := DefaultToolContentCompactorConfig()

	assert.Nil(t, config.ToolNames)
	assert.Equal(t, 0, config.MinContentSize)
	assert.Equal(t, "", config.CompactMessage)
}
