package agentconfig

import (
	"regexp"
	"strings"

	"github.com/safedep/vet/v2/internal/plugins/internal/hiddencode"
)

// pattern is one high-confidence sign of a malicious command.
type pattern struct {
	re     *regexp.Regexp
	reason string
}

// suspicious are the shared heuristics over every command that the
// controls read (control catalog, phase 4). Each one is rare in a normal
// project config.
var suspicious = []pattern{
	{regexp.MustCompile(`(?i)\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|;&]*\|\s*(sudo\s+)?(((ba|z|da|k|c|tc)?sh|fish|source|cmd(\.exe)?|powershell(\.exe)?|pwsh)\b|\.(\s|$))`), "downloads a script and pipes it to a shell"},
	{regexp.MustCompile(`(?i)\b(curl|wget)\b[^;&|]*\s(-[a-zA-Z]*[oO]|--output|--output-document)\s*\S+.*(&&|;|\|\||&)\s*(sudo\s+)?((ba|z|da|k)?sh\b|python3?\b|node\b|perl\b|ruby\b|chmod\s+\+?[0-7]*x|\./|/tmp/|"?[\w./\\-]+\.(bat|cmd|ps1|exe|sh)\b)`), "downloads a file and runs it"},
	{regexp.MustCompile(`(?i)\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^;&]*\|\s*(iex|invoke-expression)\b`), "runs the output of a download in PowerShell"},
	{regexp.MustCompile(`(?i)\b(ba|z|da|k)?sh\s+<\(\s*(curl|wget)\b`), "runs the output of a download"},
	{regexp.MustCompile(`(?i)\bfetch\s*\(.*\b(eval|Function)\b`), "fetches a script and runs it"},
	{regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;&]*\|\s*(python3?|node|perl|ruby)\b`), "downloads a script and pipes it to an interpreter"},
	{regexp.MustCompile(`(?i)\b(bash|sh|zsh)\s+-c\s+["']?\$\(\s*(curl|wget)\b`), "runs the output of a download"},
	{regexp.MustCompile(`(?i)\b(iex|invoke-expression)\b.*\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b`), "runs the output of a download in PowerShell"},
	{regexp.MustCompile(`(?i)\bbase64\s+(-\w*[dD]\w*|--decode)\b`), "decodes a base64 payload"},
	{regexp.MustCompile(`(?i)\b(powershell|pwsh)(\.exe)?\b.*\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}`), "runs an encoded PowerShell payload"},
	{regexp.MustCompile(`(?i)\b(eval|exec)\b.*\b(atob|frombase64string|b64decode)\b`), "runs a decoded payload"},
	{regexp.MustCompile(`(?i)\b(node|deno|bun|python3?|perl|ruby)(\.exe)?\s+(-e|-c|-p|--eval|--print)\b.*(buffer\.from|base64|atob|b64decode|fromcharcode|\\x[0-9a-f]{2})`), "runs an inline script that decodes a payload"},
	{regexp.MustCompile(`(?i)\bnode(\.exe)?\s+(-\S+\s+)*["']?[^\s"']*\.(` + notScripts() + `)(["'\s;&|)]|$)`), "runs a file that is not a script with node"},
	{regexp.MustCompile(`https?://[a-z0-9-]+\.vercel\.app/settings/(mac|linux|win|windows)\b`), "fetches from a URL of the shape that PolinRider tasks use"},
	{regexp.MustCompile(`\S[ \t]{50,}\S`), "hides part of the command after a run of spaces"},
	{regexp.MustCompile(`/dev/tcp/`), "opens a raw network connection from the shell"},
	{regexp.MustCompile(`(?i)\b(nc|ncat|netcat)\b.*\s-e\s`), "starts a reverse shell"},
	{regexp.MustCompile(`(?i)(~|\$home|%userprofile%)[/\\]\.(ssh|aws|gnupg|kube|docker)\b`), "reads a credential directory"},
	{regexp.MustCompile(`(?i)\.(npmrc|pypirc|netrc|git-credentials)\b`), "reads a credential file"},
}

// notScripts is the regular expression alternation of the extensions of
// the files that node must not run: the assets that the hidden-code
// controls check, and other data files.
func notScripts() string {
	exts := []string{"txt", "dat", "bin"}
	for _, e := range hiddencode.AssetExts() {
		exts = append(exts, regexp.QuoteMeta(strings.TrimPrefix(e, ".")))
	}
	return strings.Join(exts, "|")
}

// configFamily groups the config folders of a repository. Cursor reads the
// .vscode folder too, so the editor folders are one family.
var configFamily = map[string]string{".vscode": "editor", ".cursor": "editor", ".claude": "agent"}

// configScript is a script in an editor or agent config folder that an
// interpreter runs.
var configScript = regexp.MustCompile(`(?i)\b(node|deno|bun|python3?|sh|bash|zsh)(\.exe)?\s+(-\S+\s+)*["']?\S*\.(vscode|claude|cursor)[/\\]`)

// suspiciousReason returns why a command looks malicious, or "". dir is
// the config folder of the file that holds the command, such as .vscode.
// The patterns read the text as written and each form of shellForms, so a
// quote, an escape, a wrapper or a variable does not hide a pattern.
func suspiciousReason(text, dir string) string {
	forms, dynamic := shellForms(text)
	texts := append([]string{text}, forms...)
	for _, t := range texts {
		if r := patternReason(t); r != "" {
			return r
		}
	}
	for _, t := range texts {
		if r := crossFolderReason(t, dir); r != "" {
			return r
		}
	}
	if dynamic {
		return "builds a command name at run time in a pipe from a download or into a shell"
	}
	return ""
}

func patternReason(text string) string {
	for _, p := range suspicious {
		if p.re.MatchString(text) {
			return p.reason
		}
	}
	return ""
}

// crossFolderReason reports a task that runs a script of the agent folder,
// or a hook that runs a script of the editor folder. Such a command starts a
// loader that the other folder hides: each one starts the other if a
// developer removes one. A script of the own folder, such as
// .claude/hooks/format.sh, is normal, and so is a devcontainer or a user
// task that runs a script of .vscode.
func crossFolderReason(text, dir string) string {
	own, ok := configFamily[strings.ToLower(dir)]
	if !ok {
		return ""
	}
	for _, m := range configScript.FindAllStringSubmatch(text, -1) {
		if configFamily["."+strings.ToLower(m[4])] != own {
			return "runs a script from another editor or agent config folder"
		}
	}
	return ""
}
