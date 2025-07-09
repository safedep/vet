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

	// Default paths for IDE extension directories relative to home directory
	vsCodeExtPath   = ".vscode/extensions"
	vscodiumExtPath = ".vscode-oss/extensions"
	cursorExtPath   = ".cursor/extensions"
	windsurfExtPath = ".windsurf/extensions"
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

type distributionInfo struct {
	FilePath  string // Path to the extensions directory
	Ecosystem string // Type of extension marketplace (VSCode or OpenVSX)
}

type vscodeExtReader struct {
	distributions map[string]distributionInfo
}

var _ PackageManifestReader = (*vscodeExtReader)(nil)

func NewVSCodeExtReader(distributions []string) (*vscodeExtReader, error) {
	customDistributions := make(map[string]distributionInfo)
	for i, distribution := range distributions {
		customDistributions[fmt.Sprintf("custom-%d", i)] = distributionInfo{
			FilePath:  distribution,
			Ecosystem: models.EcosystemVSCodeExtensions,
		}
	}

	return newVSCodeExtReaderFromDistributions(customDistributions)
}

func NewVSCodeExtReaderFromDefaultDistributions() (*vscodeExtReader, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	distributions := map[string]distributionInfo{
		"code": {
			FilePath:  filepath.Join(homeDir, vsCodeExtPath),
			Ecosystem: models.EcosystemVSCodeExtensions,
		},
		"cursor": {
			FilePath:  filepath.Join(homeDir, cursorExtPath),
			Ecosystem: models.EcosystemOpenVSXExtensions,
		},
		"vscodium": {
			FilePath:  filepath.Join(homeDir, vscodiumExtPath),
			Ecosystem: models.EcosystemOpenVSXExtensions,
		},
		"windsurf": {
			FilePath:  filepath.Join(homeDir, windsurfExtPath),
			Ecosystem: models.EcosystemOpenVSXExtensions,
		},
	}

	return &vscodeExtReader{distributions: distributions}, nil
}

func newVSCodeExtReaderFromDistributions(d map[string]distributionInfo) (*vscodeExtReader, error) {
	return &vscodeExtReader{distributions: d}, nil
}

func (r *vscodeExtReader) Name() string {
	return "VSCode Extensions Reader"
}

func (r *vscodeExtReader) ApplicationName() (string, error) {
	return "installed-vscode-extensions", nil
}

func (r *vscodeExtReader) EnumManifests(handler func(*models.PackageManifest, PackageReader) error) error {
	for distribution := range r.distributions {
		extensions, path, err := r.readExtensions(distribution)
		if err != nil {
			logger.Errorf("failed to read extensions for distribution %s: %v", distribution, err)
			continue
		}

		info := r.distributions[distribution]
		manifest := models.NewPackageManifestFromLocal(path, info.Ecosystem)
		for _, extension := range extensions.Extensions {
			pkg := &models.Package{
				PackageDetails: models.NewPackageDetail(info.Ecosystem, extension.Identifier.Id, extension.Version),
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
	info, ok := r.distributions[distribution]
	if !ok {
		return nil, "", fmt.Errorf("distribution %s not supported", distribution)
	}

	extensionsFile := filepath.Join(info.FilePath, vsCodeExtensionExtensionsFileName)
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
