package readers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/pkg/models"
)

type jsonDumpReader struct {
	path string
}

// NewJsonDumpReader creates a [PackageManifestReader] to read JSON dumps from
// the given directory path. The JSON files in the directory must be generated
// with `--json-dump-dir` scan option. This reader will fail on first error
// while scanning and loading JSON manifests from file
func NewJsonDumpReader(path string) (PackageManifestReader, error) {
	return &jsonDumpReader{
		path: path,
	}, nil
}

// Name returns the name of this reader
func (p *jsonDumpReader) Name() string {
	return "JSON Dump Reader"
}

// EnumManifests iterates the target directory looking for only JSON files by
// extension and decoding them as [models.PackageManifest] model. Callback handler
// is invoked for each decoded package manifest
func (p *jsonDumpReader) EnumManifests(handler func(*models.PackageManifest,
	PackageReader) error) error {
	err := filepath.WalkDir(p.path, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		path, err = filepath.Abs(path)
		if err != nil {
			return err
		}

		ext := filepath.Ext(path)
		if !strings.EqualFold(ext, ".json") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		manifest := models.PackageManifest{
			DependencyGraph: models.NewDependencyGraph[*models.Package](),
		}

		err = json.Unmarshal(data, &manifest)
		if err != nil {
			return err
		}

		err = p.validateManifestModel(&manifest)
		if err != nil {
			return err
		}

		// Fix manifest path to avoid dangling paths
		manifest.Path = path

		// Fix manifest reference in each package
		for _, pkg := range manifest.GetPackages() {
			pkg.Manifest = &manifest
		}

		return handler(&manifest,
			NewManifestModelReader(&manifest))
	})

	return err
}

func (p *jsonDumpReader) validateManifestModel(m *models.PackageManifest) error {
	if utils.IsEmptyString(m.Ecosystem) {
		return fmt.Errorf("invalid manifest error: missing ecosystem")
	}

	return nil
}
