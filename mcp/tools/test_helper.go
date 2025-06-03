package tools

import (
	mcpgo "github.com/mark3labs/mcp-go/mcp"
)

func createCallToolRequest(name string, args map[string]interface{}) mcpgo.CallToolRequest {
	return mcpgo.CallToolRequest{
		Params: mcpgo.CallToolParams{
			Name:      name,
			Arguments: args,
		},
	}
}
