package readers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

const (
	vsCodeExtensionExtensionsFileName = "extensions.json"
)

var editors = map[string]distributionInfo{
	"code": {
		FilePath:  ".vscode/extensions",
		Ecosystem: models.EcosystemVSCodeExtensions,
	},
	"vscodium": {
		FilePath:  ".vscode-oss/extensions",
		Ecosystem: models.EcosystemOpenVSXExtensions,
	},
	"cursor": {
		FilePath:  ".cursor/extensions",
		Ecosystem: models.EcosystemOpenVSXExtensions,
	},
	"windsurf": {
		FilePath:  ".windsurf/extensions",
		Ecosystem: models.EcosystemOpenVSXExtensions,
	},
}

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

type vsixExtReader struct {
	distributions map[string]distributionInfo
}

var _ PackageManifestReader = (*vsixExtReader)(nil)

func NewVSIXExtReader(distributions []string) (*vsixExtReader, error) {
	customDistributions := make(map[string]distributionInfo)

	for i, distribution := range distributions {
		// Check if the path matches any supported editor
		foundMatch := false
		ecosystem := models.EcosystemVSCodeExtensions

		for _, eco := range editors {
			if strings.Contains(distribution, eco.FilePath) {
				ecosystem = eco.Ecosystem
				foundMatch = true
				break
			}
		}

		if !foundMatch {
			return nil, fmt.Errorf("unsupported editor path: %s", distribution)
		}

		customDistributions[fmt.Sprintf("custom-%d", i)] = distributionInfo{
			FilePath:  distribution,
			Ecosystem: ecosystem,
		}
	}

	return newVSCodeExtReaderFromDistributions(customDistributions)
}

func NewVSIXExtReaderFromDefaultDistributions() (*vsixExtReader, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	distributions := make(map[string]distributionInfo)
	for editorName, config := range editors {
		distributions[editorName] = distributionInfo{
			FilePath:  filepath.Join(homeDir, config.FilePath),
			Ecosystem: config.Ecosystem,
		}
	}

	return &vsixExtReader{distributions: distributions}, nil
}

func newVSCodeExtReaderFromDistributions(d map[string]distributionInfo) (*vsixExtReader, error) {
	return &vsixExtReader{distributions: d}, nil
}

func (r *vsixExtReader) Name() string {
	return "VSIX Extensions Reader"
}

func (r *vsixExtReader) ApplicationName() (string, error) {
	return "installed-vsix-extensions", nil
}

func (r *vsixExtReader) EnumManifests(handler func(*models.PackageManifest, PackageReader) error) error {
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

func (r *vsixExtReader) readExtensions(distribution string) (*vsCodeExtensionList, string, error) {
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
