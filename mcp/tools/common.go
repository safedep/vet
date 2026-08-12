package tools

import (
	"encoding/json"
	"fmt"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
)

const (
	llmResponseTypeError               = "ERROR"
	llmErrorCodePackageInsightNotFound = "PACKAGE_INSIGHT_NOT_FOUND"
	llmErrorCodeUpstreamError          = "UPSTREAM_ERROR"
)

type llmErrorResponse struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

func serializeForLlm(msg any) (string, error) {
	json, err := json.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal message to JSON: %w", err)
	}

	return fmt.Sprintf("```json\n%s\n```", string(json)), nil
}

func serializeErrorForLlm(message, code string) (string, error) {
	return serializeForLlm(llmErrorResponse{
		Type:    llmResponseTypeError,
		Message: message,
		Code:    code,
	})
}

func toolResultFromLlmError(message, code string) (*mcpgo.CallToolResult, error) {
	serialized, err := serializeErrorForLlm(message, code)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize error response: %w", err)
	}

	return mcpgo.NewToolResultText(serialized), nil
}
