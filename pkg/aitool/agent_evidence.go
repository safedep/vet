package aitool

import (
	"sort"
	"strings"
)

// Metadata keys set on every coding_agent by the post-discovery enrichment
// pass. A config file or directory alone can outlive an uninstalled agent,
// so agent.installed is true only when some other signal backs it up.
const (
	MetaAgentInstalled = "agent.installed"
	MetaAgentEvidence  = "agent.evidence"
)

// Evidence values listed in agent.evidence.
const (
	AgentEvidenceConfig    = "config"
	AgentEvidenceBinary    = "binary"
	AgentEvidenceExtension = "extension"
	AgentEvidenceAppBundle = "app_bundle"
)

// installEvidence collects, across one discovery run, which apps have a
// verified CLI binary or an installed IDE extension. Coding agents are
// joined to that evidence by App once every discoverer has run.
type installEvidence struct {
	binaryApps    map[string]bool
	extensionApps map[string]bool
}

func newInstallEvidence() *installEvidence {
	return &installEvidence{
		binaryApps:    make(map[string]bool),
		extensionApps: make(map[string]bool),
	}
}

func (e *installEvidence) observe(t *AITool) {
	switch t.Type {
	case AIToolTypeCLITool:
		if verified, _ := t.GetMeta("binary.verified").(bool); verified {
			e.binaryApps[t.App] = true
		}
	case AIToolTypeAIExtension, AIToolTypeIDEExtension:
		// Extension items carry the IDE-extension app id, not the agent's,
		// so the agent is resolved from the extension id.
		if t.Extension == nil {
			return
		}
		if info, ok := knownAIExtensions[strings.ToLower(t.Extension.ID)]; ok && info.App != "" {
			e.extensionApps[info.App] = true
		}
	}
}

// enrich sets agent.installed and agent.evidence on a coding_agent.
func (e *installEvidence) enrich(agent *AITool) {
	evidence := []string{AgentEvidenceConfig}
	if e.binaryApps[agent.App] {
		evidence = append(evidence, AgentEvidenceBinary)
	}
	if e.extensionApps[agent.App] {
		evidence = append(evidence, AgentEvidenceExtension)
	}
	if agent.InstallPath != "" {
		evidence = append(evidence, AgentEvidenceAppBundle)
	}
	sort.Strings(evidence)

	agent.SetMeta(MetaAgentInstalled, len(evidence) > 1)
	agent.SetMeta(MetaAgentEvidence, strings.Join(evidence, ","))
}
