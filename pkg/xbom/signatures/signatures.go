package signatures

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"

	callgraphv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/code/callgraph/v1"
	"github.com/safedep/code/plugin/callgraph"
	"github.com/safedep/dry/log"
	"gopkg.in/yaml.v3"
)

var signatureFiles embed.FS

func SetEmbeddedSignatureFS(files embed.FS) {
	signatureFiles = files
}

type signatureFile struct {
	Version    string                  `yaml:"version"`
	Signatures []callgraphv1.Signature `yaml:"signatures"`
}

// LoadSignatures loads the signatures from the specified vendor, product, and service.
// If a service is not specified, it will load all signatures for the given vendor and product.
// If a product is not specified, it will load all signatures for the given vendor.
// If a vendor is not specified, it will load all the signatures.
func LoadSignatures(vendor string, product string, service string) ([]*callgraphv1.Signature, error) {
	isSingleSignatureFile := false
	subDirs := []string{".", vendor}
	if product != "" {
		subDirs = append(subDirs, product)
		if service != "" {
			subDirs = append(subDirs, service+".yaml")
			isSingleSignatureFile = true
		}
	}

	signaturesPath := path.Join(subDirs...)

	log.Debugf("Reading signatures from: %s (%t)", signaturesPath, isSingleSignatureFile)

	var targetSignatures []*callgraphv1.Signature

	if isSingleSignatureFile {
		sigs, err := loadSignatureFile(signaturesPath)
		if err != nil {
			return nil, err
		}
		targetSignatures = sigs
	} else {
		err := fs.WalkDir(signatureFiles, signaturesPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}

			if filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml" {
				return nil
			}

			signatures, err := loadSignatureFile(path)
			if err != nil {
				return fmt.Errorf("failed to load signature file %s: %v", path, err)
			}

			targetSignatures = append(targetSignatures, signatures...)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to walk through signature files: %w", err)
		}
	}

	if err := callgraph.ValidateSignatures(targetSignatures); err != nil {
		return nil, fmt.Errorf("invalid signatures: %w", err)
	}

	if err := checkDuplicateSignatures(targetSignatures); err != nil {
		return nil, fmt.Errorf("duplicate signatures found: %w", err)
	}

	return targetSignatures, nil
}

// LoadAllSignatures is a wrapper to get all signatures conveniently.
func LoadAllSignatures() ([]*callgraphv1.Signature, error) {
	return LoadSignatures("", "", "")
}

func loadSignatureFile(file string) ([]*callgraphv1.Signature, error) {
	signatureData, err := signatureFiles.ReadFile(file)
	if err != nil {
		log.Errorf("Failed to read signature file: %v", err)
		return []*callgraphv1.Signature{}, err
	}

	var parsedSignatureFile signatureFile
	err = yaml.Unmarshal(signatureData, &parsedSignatureFile)
	if err != nil {
		log.Errorf("Failed to parse signature YAML - %s: %v", file, err)
		return []*callgraphv1.Signature{}, err
	}

	parsedSignatures := make([]*callgraphv1.Signature, len(parsedSignatureFile.Signatures))
	for i := range parsedSignatureFile.Signatures {
		parsedSignatures[i] = &parsedSignatureFile.Signatures[i]
	}

	return parsedSignatures, nil
}

// KnownTags returns the set of signature tags that have well-defined semantics
// and are suitable for use as CycloneDX component properties.
func KnownTags() []string {
	return []string{
		"ai",
		"cryptography",
		"encryption",
		"hash",
		"ml",
		"iaas",
		"paas",
		"saas",
	}
}

func checkDuplicateSignatures(signatures []*callgraphv1.Signature) error {
	signatureMap := make(map[string]bool)
	for _, signature := range signatures {
		if _, exists := signatureMap[signature.Id]; exists {
			return fmt.Errorf("duplicate signature - %s", signature.Id)
		}
		signatureMap[signature.Id] = true
	}
	return nil
}
