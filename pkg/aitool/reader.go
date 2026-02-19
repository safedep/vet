package aitool

// AIToolHandlerFn is called for each discovered AI tool.
// Return an error to stop enumeration.
type AIToolHandlerFn func(*AITool) error

// AIToolReader discovers AI tools from a specific source.
// Implementations should be specific to a single AI client/host
// (e.g. one reader for Claude Code, another for Cursor).
type AIToolReader interface {
	// Name returns a human-readable name for this discoverer
	Name() string

	// Host returns the AI client identifier (e.g. "claude_code", "cursor")
	Host() string

	// EnumTools discovers AI tools and calls handler for each one found.
	// Enumeration stops on first handler error.
	EnumTools(handler AIToolHandlerFn) error
}
