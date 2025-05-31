package tools

import (
	"encoding/json"
	"fmt"
)

func serializeForLlm(msg any) (string, error) {
	json, err := json.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal message to JSON: %w", err)
	}

	return fmt.Sprintf("```json\n%s\n```", string(json)), nil
}
