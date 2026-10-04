package agentconfig

import "regexp"

// pattern is one high-confidence sign of a malicious command.
type pattern struct {
	re     *regexp.Regexp
	reason string
}

// suspicious are the shared heuristics over every command that the
// controls read (control catalog, phase 4). Each one is rare in a normal
// project config.
var suspicious = []pattern{
	{regexp.MustCompile(`(?i)\b(curl|wget|iwr|invoke-webrequest)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b`), "downloads a script and pipes it to a shell"},
	{regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;&]*\|\s*(python3?|node|perl|ruby)\b`), "downloads a script and pipes it to an interpreter"},
	{regexp.MustCompile(`(?i)\b(bash|sh|zsh)\s+-c\s+["']?\$\(\s*(curl|wget)\b`), "runs the output of a download"},
	{regexp.MustCompile(`(?i)\b(iex|invoke-expression)\b.*\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b`), "runs the output of a download in PowerShell"},
	{regexp.MustCompile(`(?i)\bbase64\s+(-d|--decode|-D)\b`), "decodes a base64 payload"},
	{regexp.MustCompile(`(?i)\b(powershell|pwsh)(\.exe)?\b.*\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}`), "runs an encoded PowerShell payload"},
	{regexp.MustCompile(`(?i)\b(eval|exec)\b.*\b(atob|frombase64string|b64decode)\b`), "runs a decoded payload"},
	{regexp.MustCompile(`/dev/tcp/`), "opens a raw network connection from the shell"},
	{regexp.MustCompile(`(?i)\b(nc|ncat|netcat)\b.*\s-e\s`), "starts a reverse shell"},
	{regexp.MustCompile(`(?i)(~|\$home|%userprofile%)[/\\]\.(ssh|aws|gnupg|kube|docker)\b`), "reads a credential directory"},
	{regexp.MustCompile(`(?i)\.(npmrc|pypirc|netrc|git-credentials)\b`), "reads a credential file"},
}

// suspiciousReason returns why a command looks malicious, or "".
func suspiciousReason(text string) string {
	for _, p := range suspicious {
		if p.re.MatchString(text) {
			return p.reason
		}
	}
	return ""
}
