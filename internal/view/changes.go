package view

import (
	"context"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// CountChanges counts the changed packages and workflows of a report.
func CountChanges(ctx context.Context, r plugin.Report) (Changes, error) {
	var c Changes
	for rec, err := range r.Records(ctx) {
		if err != nil {
			return Changes{}, err
		}
		switch {
		case rec.Package != nil && rec.Package.Change.Introduces():
			c.Packages++
		case rec.Package != nil:
			c.Unchanged++
		case rec.Manifest != nil && rec.Manifest.Kind == model.ManifestKindWorkflow && rec.Manifest.Change.Introduces():
			c.Workflows++
		}
	}
	return c, nil
}
