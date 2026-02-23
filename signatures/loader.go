package signatures

import (
	"embed"

	pkgsignatures "github.com/safedep/vet/pkg/xbom/signatures"
)

//go:embed lang openai anthropic langchain crewai google microsoft cryptography
var embeddedSignatureFS embed.FS

func init() {
	pkgsignatures.SetEmbeddedSignatureFS(embeddedSignatureFS)
}
