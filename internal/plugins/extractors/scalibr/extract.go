package scalibr

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"

	"github.com/safedep/vet/v2/model"
)

// File is one file of a target.
type File struct {
	// Root is the target on disk.
	Root string
	// Path is relative to Root, with "/".
	Path string
}

// ExtractFile runs each extractor that wants the file, and converts each
// result to a manifest. An extractor error does not stop the others. The
// errors come back with the manifests.
func ExtractFile(ctx context.Context, f File, exs []filesystem.Extractor) ([]*model.Manifest, []error) {
	fsys := scalibrfs.DirFS(f.Root)
	info, err := fs.Stat(fsys, f.Path)
	if err != nil {
		return nil, []error{err}
	}
	api := simplefileapi.New(f.Path, info)

	var out []*model.Manifest
	var errs []error
	for _, e := range exs {
		if !e.FileRequired(api) {
			continue
		}
		inv, err := extractOne(ctx, e, fsys, f, info)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %s: %w", e.Name(), f.Path, err))
		}
		m, perrs := ToManifest(Input{Path: path.Clean(f.Path), Extractor: e.Name(), Root: fsys, Inventory: inv})
		errs = append(errs, perrs...)
		if m != nil {
			out = append(out, m)
		}
	}
	return out, errs
}

func extractOne(ctx context.Context, e filesystem.Extractor, fsys scalibrfs.FS, f File, info fs.FileInfo) (inv inventory.Inventory, err error) {
	r, err := fsys.Open(f.Path)
	if err != nil {
		return inv, err
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	return e.Extract(ctx, &filesystem.ScanInput{FS: fsys, Path: f.Path, Root: f.Root, Info: info, Reader: r})
}
