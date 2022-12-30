package analyzer

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

type jsonDumperAnalyzer struct {
	dir string
}

func NewJsonDumperAnalyzer(dir string) (Analyzer, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				return nil, fmt.Errorf("cannot create dir: %w", err)
			}
		}

		return nil, fmt.Errorf("cannot stat dir: %w", err)
	}

	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a dir", dir)
	}

	return &jsonDumperAnalyzer{dir: dir}, nil
}

func (j *jsonDumperAnalyzer) Name() string {
	return "JSON Dump Generator"
}

func (j *jsonDumperAnalyzer) Analyze(manifest *models.PackageManifest,
	handler AnalyzerEventHandler) error {

	logger.Infof("Running analyzer: %s", j.Name())
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("Failed to JSON serialize manifest: %w", err)
	}

	path := filepath.Join(j.dir, fmt.Sprintf("%s-%s--%d-dump.json",
		manifest.Ecosystem,
		filepath.Base(manifest.Path),
		rand.Intn(2<<15)))

	return ioutil.WriteFile(path, data, 0600)
}
