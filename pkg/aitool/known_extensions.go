package aitool

// knownAIExtensionInfo holds display metadata for a known AI extension.
// App is the coding agent app id the extension installs, when vet also
// discovers that agent's config; it links the two for install evidence.
type knownAIExtensionInfo struct {
	DisplayName string
	App         string
}

// knownAIExtensions maps lowercase extension IDs to their display info.
var knownAIExtensions = map[string]knownAIExtensionInfo{
	"github.copilot":                    {DisplayName: "GitHub Copilot"},
	"github.copilot-chat":               {DisplayName: "GitHub Copilot Chat"},
	"sourcegraph.cody-ai":               {DisplayName: "Cody"},
	"continue.continue":                 {DisplayName: "Continue", App: continueApp},
	"tabnine.tabnine-vscode":            {DisplayName: "Tabnine"},
	"amazonwebservices.amazon-q-vscode": {DisplayName: "Amazon Q", App: amazonQApp},
	"saoudrizwan.claude-dev":            {DisplayName: "Cline", App: clineApp},
	"rooveterinaryinc.roo-cline":        {DisplayName: "Roo Code", App: rooCodeApp},
	"codeium.codeium":                   {DisplayName: "Codeium"},
	"supermaven.supermaven":             {DisplayName: "Supermaven"},
	"kilocode.kilo-code":                {DisplayName: "Kilo Code"},
	"anthropic.claude-code":             {DisplayName: "Claude Code", App: claudeCodeApp},
	"openai.chatgpt":                    {DisplayName: "Codex", App: codexApp},
	"google.geminicodeassist":           {DisplayName: "Gemini Code Assist"},
	"augment.vscode-augment":            {DisplayName: "Augment Code", App: augmentApp},
}
