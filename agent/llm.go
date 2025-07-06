package agent

import (
	"context"
	"fmt"
	"os"

	"github.com/cloudwego/eino-ext/components/model/gemini"
	"github.com/cloudwego/eino/components/model"
	"google.golang.org/genai"
)

func BuildModelFromEnvironment() (model.ToolCallingChatModel, error) {
	return buildGeminiModelFromEnvironment()
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
