package analyzer

import (
	"os"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/filterinput"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

const (
	filterInputVarRoot      = "$"
	filterInputVarPkg       = "pkg"
	filterInputVarVulns     = "vulns"
	filterInputVarScorecard = "scorecard"
	filterInputVarProjects  = "projects"
	filterInputVarLicenses  = "licenses"
)

type celFilterAnalyzer struct {
	program cel.Program
}

func NewCelFilterAnalyzer(filter string) (Analyzer, error) {
	env, err := cel.NewEnv(
		cel.Variable(filterInputVarPkg, cel.DynType),
		cel.Variable(filterInputVarVulns, cel.DynType),
		cel.Variable(filterInputVarProjects, cel.DynType),
		cel.Variable(filterInputVarScorecard, cel.DynType),
		cel.Variable(filterInputVarLicenses, cel.DynType),
		cel.Variable(filterInputVarRoot, cel.DynType),
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

	tbl := table.NewWriter()
	tbl.SetStyle(table.StyleLight)
	tbl.SetOutputMirror(os.Stdout)
	tbl.AppendHeader(table.Row{"Ecosystem", "Package", "Version",
		"Latest", "Source"})

	logger.Infof("CEL filtering manifest: %s", manifest.Path)
	for _, pkg := range manifest.Packages {
		filterInput, err := f.buildFilterInput(pkg)
		if err != nil {
			logger.Errorf("Failed to convert package to filter input: %v", err)
			continue
		}

		out, _, err := f.program.Eval(map[string]interface{}{
			filterInputVarPkg:       filterInput.Pkg,
			filterInputVarProjects:  filterInput.Projects,
			filterInputVarVulns:     filterInput.Vulns,
			filterInputVarScorecard: filterInput.Scorecard,
			filterInputVarLicenses:  filterInput.Licenses,
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

func (f *celFilterAnalyzer) buildFilterInput(pkg *models.Package) (*filterinput.FilterInput, error) {
	fi := filterinput.FilterInput{
		Pkg: &filterinput.PackageVersion{
			Ecosystem: strings.ToLower(string(pkg.PackageDetails.Ecosystem)),
			Name:      pkg.PackageDetails.Name,
			Version:   pkg.PackageDetails.Version,
		},
		Projects: []*filterinput.ProjectInfo{},
		Vulns: &filterinput.Vulnerabilities{
			All:      []*filterinput.Vulnerability{},
			Critical: []*filterinput.Vulnerability{},
			High:     []*filterinput.Vulnerability{},
			Medium:   []*filterinput.Vulnerability{},
			Low:      []*filterinput.Vulnerability{},
		},
		Scorecard: &filterinput.Scorecard{
			Scores: map[string]float32{},
		},
		Licenses: []string{},
	}

	// Safely get insight
	insight := utils.SafelyGetValue(pkg.Insights)

	// Add projects
	for _, project := range utils.SafelyGetValue(insight.Projects) {
		fi.Projects = append(fi.Projects, &filterinput.ProjectInfo{
			Name:   utils.SafelyGetValue(project.Name),
			Stars:  int32(utils.SafelyGetValue(project.Stars)),
			Forks:  int32(utils.SafelyGetValue(project.Forks)),
			Issues: int32(utils.SafelyGetValue(project.Issues)),
		})
	}

	// Add vulnerabilities
	cveFilter := func(aliases []string) string {
		for _, alias := range aliases {
			if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
				return alias
			}
		}

		return ""
	}

	for _, vuln := range utils.SafelyGetValue(insight.Vulnerabilities) {
		fiv := filterinput.Vulnerability{
			Id:  utils.SafelyGetValue(vuln.Id),
			Cve: cveFilter(utils.SafelyGetValue(vuln.Aliases)),
		}

		fi.Vulns.All = append(fi.Vulns.All, &fiv)

		risk := insightapi.PackageVulnerabilitySeveritiesRiskUNKNOWN
		for _, s := range utils.SafelyGetValue(vuln.Severities) {
			sType := utils.SafelyGetValue(s.Type)
			if (sType == insightapi.PackageVulnerabilitySeveritiesTypeCVSSV3) ||
				(sType == insightapi.PackageVulnerabilitySeveritiesTypeCVSSV2) {
				risk = utils.SafelyGetValue(s.Risk)
				break
			}
		}

		switch risk {
		case insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL:
			fi.Vulns.Critical = append(fi.Vulns.Critical, &fiv)
			break
		case insightapi.PackageVulnerabilitySeveritiesRiskHIGH:
			fi.Vulns.High = append(fi.Vulns.High, &fiv)
			break
		case insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM:
			fi.Vulns.Medium = append(fi.Vulns.Medium, &fiv)
			break
		case insightapi.PackageVulnerabilitySeveritiesRiskLOW:
			fi.Vulns.Low = append(fi.Vulns.Low, &fiv)
			break
		}
	}

	// Add licenses
	for _, lic := range utils.SafelyGetValue(insight.Licenses) {
		fi.Licenses = append(fi.Licenses, string(lic))
	}

	// Scorecard
	scorecard := utils.SafelyGetValue(insight.Scorecard)
	checks := utils.SafelyGetValue(utils.SafelyGetValue(scorecard.Content).Checks)
	for _, check := range checks {
		fi.Scorecard.Scores[string(utils.SafelyGetValue(check.Name))] =
			utils.SafelyGetValue(check.Score)
	}

	return &fi, nil
}
