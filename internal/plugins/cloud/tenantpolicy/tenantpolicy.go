// Package tenantpolicy is the policy source that reads the policy of a
// SafeDep Cloud tenant. It is a stub.
//
// gap G10: the tenant policy contract of safedep/api does not exist yet.
// Until it does, the source decodes its options and returns
// plugin.ErrUnavailable, so a scan records a diagnostic and continues
// with the local policy.
package tenantpolicy

import (
	"context"
	"fmt"

	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the plugin name, plugins.tenant-policy.
const Name = "tenant-policy"

// Options are the options of the source, plugins.tenant-policy.options.
type Options struct {
	// Policy names one policy of the tenant. Empty reads the default
	// policy of the tenant.
	Policy string `json:"policy"`
}

// Source is the stub source.
type Source struct{ opts Options }

// New decodes the options.
func New(cfg plugin.Config) (plugin.PolicySource, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	return &Source{opts: o}, nil
}

// Policies returns plugin.ErrUnavailable.
func (*Source) Policies(context.Context) ([]plugin.PolicyDoc, error) {
	return nil, fmt.Errorf("the SafeDep Cloud tenant policy is not available yet, so vet applies the local policy only: %w", plugin.ErrUnavailable)
}

// OptionsSchema returns the JSON Schema of the options.
func (*Source) OptionsSchema() []byte { return optschema.Of(&Options{}) }
