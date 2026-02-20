package aitool

// knownAIExtensionInfo holds display metadata for a known AI extension.
type knownAIExtensionInfo struct {
	DisplayName string
}

// knownAIExtensions maps lowercase extension IDs to their display info.
var knownAIExtensions = map[string]knownAIExtensionInfo{
	"github.copilot":                    {DisplayName: "GitHub Copilot"},
	"github.copilot-chat":               {DisplayName: "GitHub Copilot Chat"},
	"sourcegraph.cody-ai":               {DisplayName: "Cody"},
	"continue.continue":                 {DisplayName: "Continue"},
	"tabnine.tabnine-vscode":            {DisplayName: "Tabnine"},
	"amazonwebservices.amazon-q-vscode": {DisplayName: "Amazon Q"},
	"saoudrizwan.claude-dev":            {DisplayName: "Cline"},
	"rooveterinaryinc.roo-cline":        {DisplayName: "Roo Code"},
	"codeium.codeium":                   {DisplayName: "Codeium"},
	"supermaven.supermaven":             {DisplayName: "Supermaven"},
}
