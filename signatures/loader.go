package signatures

import (
	"embed"

	pkgsignatures "github.com/safedep/vet/pkg/xbom/signatures"
)

//go:embed lang openai anthropic langchain crewai google microsoft cryptography github aws modelcontextprotocol xai mistralai cohere groq ollama huggingface togetherai fireworks perplexity vercel pydantic
var embeddedSignatureFS embed.FS

func init() {
	pkgsignatures.SetEmbeddedSignatureFS(embeddedSignatureFS)
}
