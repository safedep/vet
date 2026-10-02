// Package lockfile holds the graph-aware lockfile extractors. Each one is a
// copy of a Scalibr extractor with a patch that sets the parent ids of
// each package. Each copy keeps the Scalibr name, so it replaces the
// upstream extractor in the extractor set.
package lockfile

import (
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"

	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/packagelockjson"
)

// Extractors returns the graph-aware lockfile extractors.
func Extractors() ([]filesystem.Extractor, error) {
	cfg := &cpb.PluginConfig{}
	var out []filesystem.Extractor
	for _, newFn := range []func(*cpb.PluginConfig) (filesystem.Extractor, error){
		packagelockjson.New,
	} {
		e, err := newFn(cfg)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}
