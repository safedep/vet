package aitool

import (
	"slices"
	"strconv"
	"strings"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

// The values of agent.evidence. A config file or folder can stay after a
// user removes the agent, so config alone does not set agent.installed.
const (
	agentEvidenceConfig    = "config"
	agentEvidenceBinary    = "binary"
	agentEvidenceExtension = "extension"
	agentEvidenceAppBundle = "app_bundle"
)

// installEvidence collects the apps that have a verified CLI binary or an
// installed IDE extension in one discovery. The registry joins a coding
// agent to this evidence by its app after every discoverer has run.
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

func (e *installEvidence) observe(it *inventory.Item) {
	switch it.Kind {
	case inventory.KindCLITool:
		if it.Metadata[metaKeyBinaryVerified] == "true" {
			e.binaryApps[it.App] = true
		}
	case inventory.KindAIExtension, inventory.KindIDEExtension:
		// An extension item has the app of the extension discoverer, so the
		// extension id names the agent.
		info, ok := knownAIExtensions[strings.ToLower(it.Metadata[metaKeyExtensionID])]
		if ok && info.App != "" {
			e.extensionApps[info.App] = true
		}
	}
}

// enrich sets agent.installed and agent.evidence on a coding agent. It
// keeps the evidence that the discoverer of the agent set.
func (e *installEvidence) enrich(agent *inventory.Item) {
	evidence := agentEvidence(agent)
	evidence = append(evidence, agentEvidenceConfig)
	if e.binaryApps[agent.App] {
		evidence = append(evidence, agentEvidenceBinary)
	}
	if e.extensionApps[agent.App] {
		evidence = append(evidence, agentEvidenceExtension)
	}
	slices.Sort(evidence)
	evidence = slices.Compact(evidence)

	agent.SetMeta(metaKeyAgentInstalled, strconv.FormatBool(len(evidence) > 1))
	agent.SetMeta(metaKeyAgentEvidence, strings.Join(evidence, ","))
}

// addAgentEvidence records evidence that only the discoverer of an agent
// can see, such as an app bundle.
func addAgentEvidence(agent *inventory.Item, evidence string) {
	agent.SetMeta(metaKeyAgentEvidence, strings.Join(append(agentEvidence(agent), evidence), ","))
}

func agentEvidence(agent *inventory.Item) []string {
	if v := agent.Metadata[metaKeyAgentEvidence]; v != "" {
		return strings.Split(v, ",")
	}
	return nil
}

// markAppBundle adds app_bundle evidence when one of the documented install
// locations of the agent exists.
func markAppBundle(agent *inventory.Item, installMarkers []string) {
	if firstExistingPath(installMarkers) != "" {
		addAgentEvidence(agent, agentEvidenceAppBundle)
	}
}
