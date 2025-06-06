package tools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSerializeForLlm(t *testing.T) {
	tests := []struct {
		name          string
		input         interface{}
		expectedError bool
		expectedJSON  bool
	}{
		{
			name: "successful serialization of struct",
			input: struct {
				Name string `json:"name"`
				ID   int    `json:"id"`
			}{
				Name: "test",
				ID:   123,
			},
			expectedError: false,
			expectedJSON:  true,
		},
		{
			name:          "successful serialization of string",
			input:         "simple string",
			expectedError: false,
			expectedJSON:  true,
		},
		{
			name:          "successful serialization of nil",
			input:         nil,
			expectedError: false,
			expectedJSON:  true,
		},
		{
			name: "serialization of map",
			input: map[string]interface{}{
				"key1": "value1",
				"key2": 42,
			},
			expectedError: false,
			expectedJSON:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := serializeForLlm(tt.input)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, result)

				if tt.expectedJSON {
					// Verify the result is wrapped in JSON markdown code block
					assert.Contains(t, result, "```json\n")
					assert.Contains(t, result, "\n```")
				}
			}
		})
	}
}
