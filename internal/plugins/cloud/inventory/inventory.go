// Package inventory syncs the inventory of an endpoint audit to SafeDep
// Cloud. It is a stub.
//
// gap G11: the endpoint inventory contract of safedep/api for vet v2 does
// not exist yet. Until it does, the syncer decodes its options and
// returns plugin.ErrUnavailable, so vet endpoint audit records a
// diagnostic and keeps its local report.
package inventory

import (
	"context"
	"fmt"

	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the plugin name, plugins.cloud-inventory.
const Name = "cloud-inventory"

// Options are the options of the syncer, plugins.cloud-inventory.options.
type Options struct {
	// EndpointID names the endpoint in SafeDep Cloud. Empty uses the
	// target key of the audit, endpoint:<hostname>.
	EndpointID string `json:"endpoint_id"`
}

// Syncer sends the inventory items of an audit.
type Syncer struct{ opts Options }

// New decodes the options.
func New(cfg plugin.Config) (*Syncer, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	return &Syncer{opts: o}, nil
}

// Sync returns plugin.ErrUnavailable.
func (*Syncer) Sync(context.Context, []report.InventoryItem) error {
	return fmt.Errorf("the SafeDep Cloud inventory sync is not available yet, so vet keeps the inventory in the local report: %w", plugin.ErrUnavailable)
}

// OptionsSchema returns the JSON Schema of the options.
func (*Syncer) OptionsSchema() []byte { return optschema.Of(&Options{}) }

var _ plugin.Schemer = (*Syncer)(nil)
