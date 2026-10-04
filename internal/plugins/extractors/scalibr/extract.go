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

// ExtractFile runs each extractor that wants a file on disk, and converts
// each result to a manifest. An extractor error does not stop the others.
// The errors come back with the manifests.
func ExtractFile(ctx context.Context, f File, exs []filesystem.Extractor) ([]*model.Manifest, []error) {
	fsys := scalibrfs.DirFS(f.Root)
	info, err := fs.Stat(fsys, f.Path)
	if err != nil {
		return nil, []error{err}
	}
	return Extract(ctx, Input{FS: fsys, Root: f.Root, Path: f.Path, Info: info}, Wanted(exs, f.Path, info))
}

// Input is one file of a file system, for Extract.
type Input struct {
	// FS is a Scalibr file system, from FileSystem.
	FS fs.FS
	// Root is the root on disk, or empty for an image.
	Root string
	Path string
	Info fs.FileInfo
}

// Wanted returns the extractors that want a file.
func Wanted(exs []filesystem.Extractor, path string, info fs.FileInfo) []filesystem.Extractor {
	api := simplefileapi.New(path, info)
	var out []filesystem.Extractor
	for _, e := range exs {
		if e.FileRequired(api) {
			out = append(out, e)
		}
	}
	return out
}

// Extract runs the extractors on a file, with no FileRequired check, and
// converts each result to a manifest.
func Extract(ctx context.Context, in Input, exs []filesystem.Extractor) ([]*model.Manifest, []error) {
	f := File{Root: in.Root, Path: in.Path}
	fsys, ok := in.FS.(scalibrfs.FS)
	if !ok {
		return nil, []error{errors.New("scalibr: the input is not a Scalibr file system")}
	}
	info := in.Info
	var out []*model.Manifest
	var errs []error
	for _, e := range exs {
		inv, err := extractOne(ctx, e, fsys, f, info)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %s: %w", e.Name(), f.Path, err))
			if len(inv.Packages) == 0 {
				continue
			}
		}
		m, perrs := ToManifest(Converted{Path: path.Clean(f.Path), Extractor: e.Name(), Root: fsys, Inventory: inv})
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

// FileSystem returns the Scalibr file system of an artifact: the directory
// on disk at path, or root when it is already a Scalibr file system, as an
// image is.
func FileSystem(path string, root fs.FS) (scalibrfs.FS, error) {
	if path != "" {
		return scalibrfs.DirFS(path), nil
	}
	if fsys, ok := root.(scalibrfs.FS); ok {
		return fsys, nil
	}
	return nil, errors.New("scalibr: the artifact has no file system")
}
