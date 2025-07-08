package agent

import (
	"context"
	"fmt"
	"os"

	"github.com/cloudwego/eino-ext/components/model/claude"
	"github.com/cloudwego/eino-ext/components/model/gemini"
	"github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/components/model"
	"google.golang.org/genai"
)

// BuildModelFromEnvironment builds a model from the environment variables.
// The order of preference is:
// 1. OpenAI
// 2. Claude
// 3. Gemini
// 4. Others..
func BuildModelFromEnvironment() (model.ToolCallingChatModel, error) {
	if model, err := buildOpenAIModelFromEnvironment(); err == nil {
		return model, nil
	}

	if model, err := buildClaudeModelFromEnvironment(); err == nil {
		return model, nil
	}

	if model, err := buildGeminiModelFromEnvironment(); err == nil {
		return model, nil
	}

	return nil, fmt.Errorf("no usable LLM found for use with agent")
}

func buildOpenAIModelFromEnvironment() (*openai.ChatModel, error) {
	defaultModel := "gpt-4o"

	modelName := os.Getenv("OPENAI_MODEL_OVERRIDE")
	if modelName == "" {
		modelName = defaultModel
	}

	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("OPENAI_API_KEY is not set")
	}

	model, err := openai.NewChatModel(context.Background(), &openai.ChatModelConfig{
		Model:  modelName,
		APIKey: apiKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create openai model: %w", err)
	}

	return model, nil
}

func buildClaudeModelFromEnvironment() (*claude.ChatModel, error) {
	defaultModel := "claude-sonnet-4-20250514"

	modelName := os.Getenv("ANTHROPIC_MODEL_OVERRIDE")
	if modelName == "" {
		modelName = defaultModel
	}

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY is not set")
	}

	model, err := claude.NewChatModel(context.Background(), &claude.Config{
		Model:  modelName,
		APIKey: apiKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create claude model: %w", err)
	}

	return model, nil
}

func buildGeminiModelFromEnvironment() (*gemini.ChatModel, error) {
	defaultModel := "gemini-2.5-pro"

	modelName := os.Getenv("GEMINI_MODEL_OVERRIDE")
	if modelName == "" {
		modelName = defaultModel
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("GEMINI_API_KEY is not set")
	}

	client, err := genai.NewClient(context.Background(), &genai.ClientConfig{
		APIKey: apiKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create gemini client: %w", err)
	}

	model, err := gemini.NewChatModel(context.Background(), &gemini.Config{
		Model:  modelName,
		Client: client,
		ThinkingConfig: &genai.ThinkingConfig{
			IncludeThoughts: false,
			ThinkingBudget:  nil,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create gemini model: %w", err)
	}

	return model, nil
}
