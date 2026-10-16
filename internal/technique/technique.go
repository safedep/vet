// Package technique is the registry of the attack techniques that vet
// detects. A technique is the unit of a contribution: a Go detector, the
// MITRE ATT&CK ids that it maps to, and the evasion corpus groups that test
// it. An attack control names its technique in plugin.ControlInfo, and the
// engine copies the ATT&CK ids onto each finding of the control.
package technique

import "slices"

// The ids of the techniques.
const (
	MaliciousPackage = "malicious-package"
	ImpostorCommit   = "impostor-commit"
	ConfigCommand    = "config-command"
	PaddedCode       = "padded-code"
	DisguisedScript  = "disguised-script"
	UnicodePayload   = "unicode-payload"
	HistoryRewrite   = "history-rewrite"
)

// Technique is one attack technique.
type Technique struct {
	ID   string
	Name string
	// MITRE holds the MITRE ATT&CK technique ids, as T1027 or T1036.008.
	MITRE []string
	// Corpus holds the groups of test/evasion/cases that test the
	// technique.
	Corpus []string
	// NoCorpus says why the technique has no corpus group. Only a technique
	// that external data decides, such as a threat intel verdict, has one.
	NoCorpus string
}

var all = []Technique{
	{
		ID: MaliciousPackage, Name: "Malicious package", MITRE: []string{"T1195.001"},
		NoCorpus: "SafeDep Threat Intel decides the verdict, so a file of the corpus cannot test it.",
	},
	{
		ID: ImpostorCommit, Name: "Action pinned to a commit outside its repository", MITRE: []string{"T1195.001", "T1036"},
		NoCorpus: "The GitHub API decides it, and the corpus runs with no network.",
	},
	{ID: ConfigCommand, Name: "Command in an agent or editor config", MITRE: []string{"T1546", "T1059"}, Corpus: []string{"commands", "variants"}},
	{ID: PaddedCode, Name: "Script hidden after a run of spaces", MITRE: []string{"T1027", "T1564"}, Corpus: []string{"padding", "placement", "variants"}},
	{ID: DisguisedScript, Name: "Script in a file of another type", MITRE: []string{"T1036.008", "T1027.009"}, Corpus: []string{"disguise", "variants"}},
	{ID: UnicodePayload, Name: "Payload in invisible Unicode characters", MITRE: []string{"T1027"}, Corpus: []string{"unicode", "variants"}},
	{ID: HistoryRewrite, Name: "Script that rewrites the git history", MITRE: []string{"T1070"}, Corpus: []string{"variants"}},
}

// All returns the techniques in registry order.
func All() []Technique { return slices.Clone(all) }

// Get returns the technique of an id.
func Get(id string) (Technique, bool) {
	i := slices.IndexFunc(all, func(t Technique) bool { return t.ID == id })
	if i < 0 {
		return Technique{}, false
	}
	return all[i], true
}
