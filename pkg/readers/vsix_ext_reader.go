package readers

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

const (
	vsCodeExtensionExtensionsFileName = "extensions.json"
)

var editors = map[string]distributionInfo{
	"code":        {FilePath: ".vscode/extensions", Ecosystem: models.EcosystemVSCodeExtensions, DisplayName: "VS Code"},
	"vscodium":    {FilePath: ".vscode-oss/extensions", Ecosystem: models.EcosystemOpenVSXExtensions, DisplayName: "VSCodium"},
	"cursor":      {FilePath: ".cursor/extensions", Ecosystem: models.EcosystemOpenVSXExtensions, DisplayName: "Cursor"},
	"windsurf":    {FilePath: ".windsurf/extensions", Ecosystem: models.EcosystemOpenVSXExtensions, DisplayName: "Windsurf"},
	"antigravity": {FilePath: ".antigravity/extensions", Ecosystem: models.EcosystemOpenVSXExtensions, DisplayName: "Antigravity"},
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
	FilePath    string
	Ecosystem   string
	DisplayName string
}

type vsixExtReader struct {
	distributions map[string]distributionInfo
}

var _ PackageManifestReader = (*vsixExtReader)(nil)

func NewVSIXExtReader(distributions []string) (*vsixExtReader, error) {
	customDistributions := make(map[string]distributionInfo)

	for i, distribution := range distributions {
		eco := detectEcosystem(distribution)
		if eco == "" {
			return nil, fmt.Errorf("unsupported editor path: %s", distribution)
		}

		customDistributions[fmt.Sprintf("custom-%d", i)] = distributionInfo{
			FilePath:  distribution,
			Ecosystem: eco,
		}
	}

	return newVSCodeExtReaderFromDistributions(customDistributions)
}

// detectEcosystem returns the marketplace ecosystem for a given extensions
// directory path by comparing path components, not substrings. This handles
// OS-native path separators correctly on all platforms (\ on Windows, / on
// Linux and macOS).
func detectEcosystem(distribution string) string {
	// Compare the last two path components (e.g. ".vscode" / "extensions")
	// against the known editor patterns so no string/separator assumptions
	// are made.
	distBase := filepath.Base(distribution)                 // "extensions"
	distEditor := filepath.Base(filepath.Dir(distribution)) // ".vscode"

	for _, eco := range editors {
		ecoBase := filepath.Base(eco.FilePath)                 // "extensions"
		ecoEditor := filepath.Base(filepath.Dir(eco.FilePath)) // ".vscode"

		if distBase == ecoBase && distEditor == ecoEditor {
			return eco.Ecosystem
		}
	}
	return ""
}

// EditorDisplayName returns the display name for an IDE given the base name of
// its extensions parent directory (e.g. ".vscode" → "VS Code"). Returns empty
// string for unrecognised dirs.
func EditorDisplayName(extDirBase string) string {
	for _, e := range editors {
		if filepath.Base(filepath.Dir(e.FilePath)) == extDirBase {
			return e.DisplayName
		}
	}
	return ""
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
			// Distribution not installed on this machine: expected.
			if errors.Is(err, os.ErrNotExist) {
				logger.Debugf("extensions for distribution %s not present: %v", distribution, err)
			} else {
				logger.Warnf("failed to read extensions for distribution %s: %v", distribution, err)
			}
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
