package analyzer

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

type celFilterAnalyzer struct {
	program cel.Program
}

func NewCelFilterAnalyzer(filter string) (Analyzer, error) {
	env, err := cel.NewEnv(
		cel.Variable("pkg", cel.DynType),
		cel.Variable("manifest", cel.DynType),
	)

	if err != nil {
		return nil, err
	}

	ast, issues := env.Compile(filter)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}

	prog, err := env.Program(ast)
	if err != nil {
		return nil, err
	}

	return &celFilterAnalyzer{program: prog}, nil
}

func (f *celFilterAnalyzer) Name() string {
	return "CEL Filter Analyzer"
}

func (f *celFilterAnalyzer) Analyze(manifest *models.PackageManifest,
	handler AnalyzerEventHandler) error {

	pkgManifestVal, err := f.valType(manifest)
	if err != nil {
		logger.Errorf("Failed to convert manifest to val: %v", err)
	}

	logger.Infof("CEL filtering manifest: %s", manifest.Path)
	for _, pkg := range manifest.Packages {
		pkgVal, err := f.valType(pkg)
		if err != nil {
			logger.Errorf("Failed to convert package to val: %v", err)
			continue
		}

		out, _, err := f.program.Eval(map[string]interface{}{
			"pkg":      pkgVal,
			"manifest": pkgManifestVal,
		})

		if err != nil {
			logger.Errorf("Failed to evaluate CEL for %s:%v : %v",
				pkg.PackageDetails.Name,
				pkg.PackageDetails.Version, err)
			continue
		}

		if (reflect.TypeOf(out).Kind() == reflect.Bool) &&
			(reflect.ValueOf(out).Bool()) {
			fmt.Printf("[%s] %s %v\n", pkg.PackageDetails.Ecosystem,
				pkg.PackageDetails.Name, pkg.PackageDetails.Version)
		}
	}

	return nil
}

func (f *celFilterAnalyzer) valType(i any) (any, error) {
	data, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}

	ret := make(map[string]interface{})
	err = json.Unmarshal(data, &ret)
	if err != nil {
		return nil, err
	}

	return ret, nil
}
