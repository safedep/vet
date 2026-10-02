package parser

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/osv-scalibr/enricher"
	pomenricher "github.com/google/osv-scalibr/enricher/transitivedependency/pomxml"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin/config"

	"github.com/safedep/vet/v2/pkg/models"
)

func parseMavenPomXmlFile(lockfilePath string, _ *ParserConfig) (*models.PackageManifest, error) {
	abs, err := filepath.Abs(lockfilePath)
	if err != nil {
		return nil, err
	}
	root, rel := filepath.Dir(abs), filepath.Base(abs)

	ext, err := pomxml.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create pom.xml extractor: %w", err)
	}

	file, err := os.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("failed to open lockfile: %w", err)
	}
	defer file.Close()

	inv, err := ext.Extract(context.Background(), &filesystem.ScanInput{
		FS: scalibrfs.DirFS(root), Path: rel, Root: root, Reader: file,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to extract packages: %w", err)
	}
	for _, p := range inv.Packages {
		p.Plugins = []string{pomxml.Name}
	}

	enr, err := pomenricher.New(config.DefaultPluginConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create pom.xml resolver: %w", err)
	}
	if err := enr.Enrich(context.Background(), &enricher.ScanInput{
		ScanRoot: scalibrfs.RealFSScanRoot(root),
	}, &inv); err != nil {
		return nil, fmt.Errorf("failed to resolve dependencies: %w", err)
	}

	manifest := models.NewPackageManifestFromLocal(lockfilePath, models.EcosystemMaven)
	for _, pkg := range inv.Packages {
		manifest.AddPackage(&models.Package{
			PackageDetails: models.NewPackageDetail(models.EcosystemMaven, pkg.Name, pkg.Version),
			Manifest:       manifest,
		})
	}
	return manifest, nil
}
