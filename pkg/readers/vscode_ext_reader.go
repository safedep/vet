package readers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

const (
	vsCodeExtensionExtensionsFileName = "extensions.json"
)

type vsCodeExtensionIdentifier struct {
	Id   string `json:"id"`
	Uuid string `json:"uuid"`
}

type vsCodeExtensionLocation struct {
	Path   string `json:"path"`
	Scheme string `json:"scheme"`
}

type vsCodeExtension struct {
	Identifier       vsCodeExtensionIdentifier `json:"identifier"`
	Version          string                    `json:"version"`
	Location         vsCodeExtensionLocation   `json:"location"`
	RelativeLocation string                    `json:"relativeLocation"`
}

type vsCodeExtensionList struct {
	Extensions []vsCodeExtension
}

type vscodeExtReader struct {
	distributionHomeDir map[string]string
}

var _ PackageManifestReader = (*vscodeExtReader)(nil)

func NewVSCodeExtReader(distributions []string) (*vscodeExtReader, error) {
	customDistributions := make(map[string]string)
	for i, distribution := range distributions {
		customDistributions[fmt.Sprintf("custom-%d", i)] = distribution
	}

	return newVSCodeExtReaderFromDistributions(customDistributions)
}

func NewVSCodeExtReaderFromDefaultDistributions() (*vscodeExtReader, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	distributionHomeDir := map[string]string{
		"code":   filepath.Join(homeDir, ".vscode", "extensions"),
		"cursor": filepath.Join(homeDir, ".cursor", "extensions"),
	}

	return &vscodeExtReader{distributionHomeDir: distributionHomeDir}, nil
}

func newVSCodeExtReaderFromDistributions(d map[string]string) (*vscodeExtReader, error) {
	return &vscodeExtReader{distributionHomeDir: d}, nil
}

func (r *vscodeExtReader) Name() string {
	return "VSCode Extensions Reader"
}

func (r *vscodeExtReader) EnumManifests(handler func(*models.PackageManifest, PackageReader) error) error {
	for distribution := range r.distributionHomeDir {
		extensions, path, err := r.readExtensions(distribution)
		if err != nil {
			logger.Errorf("failed to read extensions for distribution %s: %v", distribution, err)
			continue
		}

		manifest := models.NewPackageManifestFromLocal(path, models.EcosystemVSCodeExtensions)
		for _, extension := range extensions.Extensions {
			pkg := &models.Package{
				PackageDetails: models.NewPackageDetail(models.EcosystemVSCodeExtensions, extension.Identifier.Id, extension.Version),
			}

			manifest.AddPackage(pkg)
		}

		err = handler(manifest, NewManifestModelReader(manifest))
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *vscodeExtReader) readExtensions(distribution string) (*vsCodeExtensionList, string, error) {
	if _, ok := r.distributionHomeDir[distribution]; !ok {
		return nil, "", fmt.Errorf("distribution %s not supported", distribution)
	}

	extensionsFile := filepath.Join(r.distributionHomeDir[distribution], vsCodeExtensionExtensionsFileName)
	if _, err := os.Stat(extensionsFile); os.IsNotExist(err) {
		return nil, "", fmt.Errorf("extensions file does not exist: %w", err)
	}

	file, err := os.Open(extensionsFile)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open extensions file: %w", err)
	}

	defer file.Close()

	var extensions vsCodeExtensionList
	if err := json.NewDecoder(file).Decode(&extensions.Extensions); err != nil {
		return nil, "", fmt.Errorf("failed to decode extensions file: %w", err)
	}

	return &extensions, extensionsFile, nil
}
