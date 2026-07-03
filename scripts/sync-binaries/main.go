// Sync binaries to packages directory from goreleaser's dist/ directory.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/go-playground/validator/v10"
)

type GoreleaserArtifact struct {
	Path   string `json:"path"   validate:"required"`
	Goos   string `json:"goos"   validate:"required"`
	Goarch string `json:"goarch"`
	Type   string `json:"type"   validate:"required"`
}

var goArchToNodeArchMap = map[string]string{
	"amd64": "x64",
	"386":   "x86",
	"arm64": "arm64",
}

var goOsToNodeOsMap = map[string]string{
	"windows": "win32",
}

func main() {
	artifactsPath := flag.String("artifacts-path", "dist/artifacts.json", "Path to goreleaser artifacts.json")
	packagesPath := flag.String("packages-path", "./packages", "Path to the npm packages directory")
	strict := flag.Bool("strict", true, "Fail if a package directory does not exist for a built artifact")
	setVersion := flag.String("set-version", "", "Semver x.y.z to write into all non-private package.json files under packages-path")
	verifyBins := flag.Bool("verify-bins", false, "Verify that each platform package has a non-empty bin/ directory after sync")
	flag.Parse()

	artifactsBytes, err := os.ReadFile(*artifactsPath)
	if err != nil {
		log.Fatalf("failed to read artifacts.json (did you run goreleaser build?): %v", err)
	}

	var artifacts []GoreleaserArtifact
	if err := json.Unmarshal(artifactsBytes, &artifacts); err != nil {
		log.Fatalf("failed to parse artifacts.json: %v", err)
	}

	validate := validator.New(validator.WithRequiredStructEnabled())

	for _, artifact := range artifacts {
		switch artifact.Type {
		case "Binary":
			if err := validate.Struct(artifact); err != nil {
				log.Printf("skipping invalid artifact: %v", err)
				continue
			}

			// goreleaser v2 emits a universal macOS binary as type "Binary"
			// with goarch "all" when universal_binaries.replace is true.
			// Copy it to both darwin platform packages.
			if artifact.Goos == "darwin" && artifact.Goarch == "all" {
				for _, nodeArch := range []string{"x64", "arm64"} {
					packagePath := filepath.Join(*packagesPath, fmt.Sprintf("vet-darwin-%s", nodeArch))
					if err := copyToBin(artifact.Path, packagePath, "vet", *strict); err != nil {
						log.Fatalf("sync darwin universal -> %s: %v", nodeArch, err)
					}
				}
				continue
			}

			if err := syncBinary(artifact, *packagesPath, *strict); err != nil {
				log.Fatalf("sync: %v", err)
			}

		case "Universal Binary":
			// Retained for compatibility with older goreleaser versions that
			// emitted a distinct type for universal binaries.
			if artifact.Goos != "darwin" {
				log.Printf("unexpected universal binary for goos=%s, skipping", artifact.Goos)
				continue
			}
			for _, nodeArch := range []string{"x64", "arm64"} {
				packagePath := filepath.Join(*packagesPath, fmt.Sprintf("vet-darwin-%s", nodeArch))
				if err := copyToBin(artifact.Path, packagePath, "vet", *strict); err != nil {
					log.Fatalf("sync darwin universal -> %s: %v", nodeArch, err)
				}
			}
		}
	}

	if *setVersion != "" {
		if err := setPackageVersions(*packagesPath, *setVersion); err != nil {
			log.Fatalf("set-version: %v", err)
		}
	}

	if *verifyBins {
		if err := verifyPackageBins(*packagesPath); err != nil {
			log.Fatalf("verify-bins: %v", err)
		}
	}
}

func syncBinary(artifact GoreleaserArtifact, packagesPath string, strict bool) error {
	nodeArch, ok := goArchToNodeArchMap[artifact.Goarch]
	if !ok {
		nodeArch = artifact.Goarch
	}
	nodeOs, ok := goOsToNodeOsMap[artifact.Goos]
	if !ok {
		nodeOs = artifact.Goos
	}

	packagePath := filepath.Join(packagesPath, fmt.Sprintf("vet-%s-%s", nodeOs, nodeArch))
	binName := "vet"
	if artifact.Goos == "windows" {
		binName = "vet.exe"
	}
	return copyToBin(artifact.Path, packagePath, binName, strict)
}

func copyToBin(src, packagePath, binName string, strict bool) error {
	if _, err := os.Stat(packagePath); os.IsNotExist(err) {
		if strict {
			return fmt.Errorf("package directory %s does not exist (add the platform package or remove the goreleaser target)", packagePath)
		}
		log.Printf("package directory %s does not exist, skipping", packagePath)
		return nil
	}

	binDir := filepath.Join(packagePath, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil { //nolint:gosec // bin/ needs execute permission
		return fmt.Errorf("create bin dir %s: %w", binDir, err)
	}

	dst := filepath.Join(binDir, binName)
	log.Printf("copying %s -> %s", src, dst)
	return copyFile(src, dst)
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer srcFile.Close() //nolint:errcheck // read-only; close error is negligible

	dstFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	defer dstFile.Close() //nolint:errcheck // Sync() is called explicitly before return; deferred close is best-effort

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	if err := dstFile.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}

	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}
	return os.Chmod(dst, srcInfo.Mode())
}
