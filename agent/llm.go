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

// Map of fast vs. default models.
var defaultModelMap = map[string]map[string]string{
	"openai": {
		"default": "gpt-4o",
		"fast":    "gpt-4o-mini",
	},
	"claude": {
		"default": "claude-sonnet-4-20250514",
		"fast":    "claude-sonnet-4-20250514",
	},
	"gemini": {
		"default": "gemini-2.5-pro",
		"fast":    "gemini-2.5-flash",
	},
}

type Model struct {
	Vendor string
	Name   string
	Fast   bool
	Client model.ToolCallingChatModel
}

// BuildModelFromEnvironment builds a model from the environment variables.
// The order of preference is:
// 1. OpenAI
// 2. Claude
// 3. Gemini
// 4. Others..
//
// When enableThinking is true, models that support reasoning/thinking content
// will be configured to include it in responses (e.g. Gemini's IncludeThoughts).
func BuildModelFromEnvironment(fastMode bool, enableThinking bool) (*Model, error) {
	if model, err := buildOpenAIModelFromEnvironment(fastMode); err == nil {
		return model, nil
	}

	if model, err := buildClaudeModelFromEnvironment(fastMode); err == nil {
		return model, nil
	}

	if model, err := buildGeminiModelFromEnvironment(fastMode, enableThinking); err == nil {
		return model, nil
	}

	return nil, fmt.Errorf("no usable LLM found for use with agent")
}

func buildOpenAIModelFromEnvironment(fastMode bool) (*Model, error) {
	defaultModel := defaultModelMap["openai"]["default"]
	if fastMode {
		defaultModel = defaultModelMap["openai"]["fast"]
	}

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

	return &Model{
		Vendor: "openai",
		Name:   modelName,
		Fast:   fastMode,
		Client: model,
	}, nil
}

func buildClaudeModelFromEnvironment(fastMode bool) (*Model, error) {
	defaultModel := defaultModelMap["claude"]["default"]
	if fastMode {
		defaultModel = defaultModelMap["claude"]["fast"]
	}

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

	return &Model{
		Vendor: "claude",
		Name:   modelName,
		Fast:   fastMode,
		Client: model,
	}, nil
}

func buildGeminiModelFromEnvironment(fastMode bool, enableThinking bool) (*Model, error) {
	defaultModel := defaultModelMap["gemini"]["default"]
	if fastMode {
		defaultModel = defaultModelMap["gemini"]["fast"]
	}

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

	var thinkingConfig *genai.ThinkingConfig
	if enableThinking {
		thinkingConfig = &genai.ThinkingConfig{
			IncludeThoughts: true,
		}
	}

	model, err := gemini.NewChatModel(context.Background(), &gemini.Config{
		Model:          modelName,
		Client:         client,
		ThinkingConfig: thinkingConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create gemini model: %w", err)
	}

	return &Model{
		Vendor: "gemini",
		Name:   modelName,
		Fast:   fastMode,
		Client: model,
	}, nil
}
