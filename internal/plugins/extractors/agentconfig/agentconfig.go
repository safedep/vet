// Package agentconfig is the extractor of the agent and editor config
// files: editor tasks, agent hooks, devcontainer commands, git hooks, MCP
// configs and agent instructions. A file yields a manifest with no
// package, and the agentconfig control reads the file.
package agentconfig

import (
	"context"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"

	"github.com/safedep/vet/v2/internal/plugins/internal/agentfiles"
)

// Name is the extractor name.
const Name = "agent/config"

// maxSize skips a config file larger than 1 MiB.
const maxSize = 1 << 20

// Extractor matches the agent and editor config files.
type Extractor struct{}

// New returns the extractor.
func New() filesystem.Extractor { return Extractor{} }

// Name of the extractor.
func (Extractor) Name() string { return Name }

// Version of the extractor.
func (Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired reports an agent or editor config file.
func (Extractor) FileRequired(api filesystem.FileAPI) bool {
	if _, ok := agentfiles.Classify(filepath.ToSlash(api.Path())); !ok {
		return false
	}
	fi, err := api.Stat()
	return err == nil && fi.Size() <= maxSize
}

// Extract yields no package. The manifest of the file is enough for the
// control.
func (Extractor) Extract(context.Context, *filesystem.ScanInput) (inventory.Inventory, error) {
	return inventory.Inventory{}, nil
}
