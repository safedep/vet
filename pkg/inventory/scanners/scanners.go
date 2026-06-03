// Package scanners is the single source of truth for inventory.Scanner
// factories. The cmd layer calls Build to materialise the requested set;
// nothing else in the codebase should know which scanner packages exist.
//
// To add a new scanner:
//
//  1. Create a sub-package under pkg/inventory/scanners/<name> that exports
//     a New(...) returning inventory.Scanner.
//  2. Append a Descriptor literal to the registry below.
//
// That is the entire change set. cmd/ does not need to be touched.
package scanners

import (
	"fmt"

	"github.com/safedep/vet/pkg/aitool"
	"github.com/safedep/vet/pkg/inventory"
	aitoolscanner "github.com/safedep/vet/pkg/inventory/scanners/aitool"
	skillsscanner "github.com/safedep/vet/pkg/inventory/scanners/skills"
)

// Descriptor declares one scanner: the Kind token accepted on the
// --kind flag and the factory that constructs the scanner. Build calls
// New each time so scanners with mutable state are not shared across
// runs.
type Descriptor struct {
	Kind string
	New  func() inventory.Scanner
}

// Kind values accepted on the --kind flag and consumed by callers that
// pin a specific scanner (e.g. cmd/ai/discover).
const (
	KindAITool       = "ai-tool"
	KindAgentSkill   = "agent-skill"
	KindIDEExtension = "ide-extension"
)

// registry is the shipped set of scanner declarations. Adding a scanner
// is a PR that appends one entry here.
var registry = []Descriptor{
	{
		Kind: KindAITool,
		New: func() inventory.Scanner {
			return aitoolscanner.New(aitool.DefaultRegistry())
		},
	},
	{
		Kind: KindAgentSkill,
		New: func() inventory.Scanner {
			return skillsscanner.New()
		},
	},
	{
		// ide-extension uses an isolated registry so it never leaks into
		// vet ai discover, which pins {ai-tool, agent-skill} explicitly.
		Kind: KindIDEExtension,
		New: func() inventory.Scanner {
			reg := aitool.NewRegistry()
			reg.Register("ide_extension", aitool.NewIDEExtensionDiscoverer)
			return aitoolscanner.New(reg)
		},
	},
}

// Build returns the scanners matching the requested kind allowlist. An
// empty (or nil) kinds slice means "all kinds". An unknown kind is an
// error.
func Build(kinds []string) ([]inventory.Scanner, error) {
	wanted, err := selectDescriptors(kinds)
	if err != nil {
		return nil, err
	}
	out := make([]inventory.Scanner, 0, len(wanted))
	for _, d := range wanted {
		out = append(out, d.New())
	}
	return out, nil
}

// AllowedKinds returns the set of accepted --kind values, derived from
// the registry. Order matches registration order.
func AllowedKinds() []string {
	out := make([]string, len(registry))
	for i, d := range registry {
		out[i] = d.Kind
	}
	return out
}

// selectDescriptors filters the registry by the requested kinds. An
// empty input selects every descriptor.
func selectDescriptors(kinds []string) ([]Descriptor, error) {
	if len(kinds) == 0 {
		out := make([]Descriptor, len(registry))
		copy(out, registry)
		return out, nil
	}
	byKind := make(map[string]Descriptor, len(registry))
	for _, d := range registry {
		byKind[d.Kind] = d
	}
	out := make([]Descriptor, 0, len(kinds))
	for _, k := range kinds {
		d, ok := byKind[k]
		if !ok {
			return nil, fmt.Errorf("unsupported scanner kind %q (allowed: %v)", k, AllowedKinds())
		}
		out = append(out, d)
	}
	return out, nil
}
