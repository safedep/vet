package analyzer

import (
	"encoding/json"
	"os"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/safedep/dry/utils"
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

	tbl := table.NewWriter()
	tbl.SetStyle(table.StyleLight)
	tbl.SetOutputMirror(os.Stdout)
	tbl.AppendHeader(table.Row{"Ecosystem", "Package", "Version",
		"Latest", "Source"})

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
			tbl.AppendRow(table.Row{pkg.PackageDetails.Ecosystem,
				pkg.PackageDetails.Name,
				pkg.PackageDetails.Version,
				f.pkgLatestVersion(pkg),
				f.pkgSource(pkg),
			})
		}
	}

	tbl.Render()
	return nil
}

func (f *celFilterAnalyzer) pkgLatestVersion(pkg *models.Package) string {
	insight := utils.SafelyGetValue(pkg.Insights)
	return utils.SafelyGetValue(insight.PackageCurrentVersion)
}

func (f *celFilterAnalyzer) pkgSource(pkg *models.Package) string {
	insight := utils.SafelyGetValue(pkg.Insights)
	projects := utils.SafelyGetValue(insight.Projects)

	if len(projects) > 0 {
		return utils.SafelyGetValue(projects[0].Link)
	}

	return ""
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
