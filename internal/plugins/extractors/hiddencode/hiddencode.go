// Package hiddencode is the extractor of the files that can hide code:
// build configs, assets, source files and scripts. It yields a manifest
// with no package, and only for a file that shows a sign of hidden code.
// The hidden-code control reads the file.
package hiddencode

import (
	"context"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"

	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
	"github.com/safedep/vet/v2/internal/plugins/internal/hiddencode"
)

// Name is the extractor name.
const Name = "code/hidden"

// Extractor matches the files that can hide code.
type Extractor struct{}

// New returns the extractor.
func New() filesystem.Extractor { return Extractor{} }

// Name of the extractor.
func (Extractor) Name() string { return Name }

// Version of the extractor.
func (Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired reports a file that can hide code, of any size.
func (Extractor) FileRequired(api filesystem.FileAPI) bool {
	_, ok := hiddencode.Classify(filepath.ToSlash(api.Path()))
	return ok
}

// Extract yields no package. A file with no sign of hidden code gives
// scalibr.ErrNoManifest, so it adds nothing to the report.
func (Extractor) Extract(_ context.Context, in *filesystem.ScanInput) (inventory.Inventory, error) {
	p := filepath.ToSlash(in.Path)
	c, ok := hiddencode.Classify(p)
	if !ok {
		return inventory.Inventory{}, scalibr.ErrNoManifest
	}
	data, err := hiddencode.Read(in.FS, p, c)
	if err != nil {
		return inventory.Inventory{}, err
	}
	if len(hiddencode.Analyze(c, p, data)) == 0 {
		return inventory.Inventory{}, scalibr.ErrNoManifest
	}
	return inventory.Inventory{}, nil
}
