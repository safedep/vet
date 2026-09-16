package aitool

// knownAIExtensionInfo holds display metadata for a known AI extension.
type knownAIExtensionInfo struct {
	DisplayName string
}

// knownAIExtensions maps lowercase extension IDs to their display info.
var knownAIExtensions = map[string]knownAIExtensionInfo{
	// GitHub Copilot
	"github.copilot":      {DisplayName: "GitHub Copilot"},
	"github.copilot-chat": {DisplayName: "GitHub Copilot Chat"},

	// Google AI
	"google.gemini-code-assist": {DisplayName: "Gemini Code Assist"},
	"google.cloud-code":         {DisplayName: "Google Cloud Code"},

	// Anthropic / Claude
	"saoudrizwan.claude-dev": {DisplayName: "Cline"},

	// Amazon
	"amazonwebservices.amazon-q-vscode": {DisplayName: "Amazon Q"},

	// Sourcegraph
	"sourcegraph.cody-ai": {DisplayName: "Cody"},

	// Continue
	"continue.continue": {DisplayName: "Continue"},

	// Roo Code / Cline variants
	"rooveterinaryinc.roo-cline":      {DisplayName: "Roo Code"},
	"kodu-ai.claude-dev-experimental": {DisplayName: "Kodu AI"},

	// Codeium / Windsurf
	"codeium.codeium":       {DisplayName: "Codeium"},
	"codeium.windsurf-next": {DisplayName: "Windsurf"},

	// Tabnine
	"tabnine.tabnine-vscode": {DisplayName: "Tabnine"},

	// Supermaven
	"supermaven.supermaven": {DisplayName: "Supermaven"},

	// Augment Code
	"augment.vscode-augment": {DisplayName: "Augment Code"},

	// Microsoft IntelliCode
	"visualstudioexptteam.vscodeintellicode":              {DisplayName: "IntelliCode"},
	"visualstudioexptteam.intellicode-api-usage-examples": {DisplayName: "IntelliCode API Usage Examples"},

	// Blackbox AI
	"blackboxapp.blackbox": {DisplayName: "Blackbox AI"},

	// Pieces for Developers
	"meshintelligenttechnologiesinc.pieces-vscode": {DisplayName: "Pieces for Developers"},

	// Cursor (extension variant)
	"cursor.cursor": {DisplayName: "Cursor"},
}
