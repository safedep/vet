package filterv2

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"

	"github.com/github/go-spdx/v2/spdxexp"
)

const (
	// Policy Input v2 variable names for CEL expressions
	policyInputVarRoot       = "_"
	policyInputVarPackage    = "package"
	policyInputVarProject    = "project"
	policyInputVarManifest   = "manifest"

	// Soft limit to start with
	filterEvalMaxFilters = 50
)

var errMaxFilter = errors.New("max filter limit has reached")

// EvaluatorV2 interface for the new policy system using Insights v2 data model
type EvaluatorV2 interface {
	AddRule(rule *policyv1.Rule) error
	AddPolicy(policy *policyv1.Policy) error
	EvalPackage(pkg *models.Package) (*FilterEvaluationResult, error)
}

type filterEvaluatorV2 struct {
	name        string
	env         *cel.Env
	programs    []*FilterProgram
	ignoreError bool
}

// NewEvaluatorV2 creates a new CEL evaluator for the policy system v2
func NewEvaluatorV2(name string, ignoreError bool) (EvaluatorV2, error) {
	env, err := cel.NewEnv(
		cel.Variable(policyInputVarRoot, cel.DynType),
		cel.Variable(policyInputVarPackage, cel.DynType),
		cel.Variable(policyInputVarProject, cel.DynType),
		cel.Variable(policyInputVarManifest, cel.DynType),
		cel.Function("contains_license",
			cel.MemberOverload("list_string_contains_license_string",
				[]*cel.Type{cel.ListType(cel.StringType), cel.StringType}, cel.BoolType,
				cel.BinaryBinding(celFuncLicenseExpressionMatch()))))
	if err != nil {
		return nil, err
	}

	return &filterEvaluatorV2{
		name:        name,
		env:         env,
		programs:    []*FilterProgram{},
		ignoreError: ignoreError,
	}, nil
}

func (f *filterEvaluatorV2) AddRule(rule *policyv1.Rule) error {
	if len(f.programs) >= filterEvalMaxFilters {
		return errMaxFilter
	}

	ast, issues := f.env.Compile(rule.GetValue())
	if issues != nil && issues.Err() != nil {
		return issues.Err()
	}

	prog, err := f.env.Program(ast)
	if err != nil {
		return err
	}

	f.programs = append(f.programs, &FilterProgram{
		rule:    rule,
		program: prog,
	})

	return nil
}

func (f *filterEvaluatorV2) AddPolicy(policy *policyv1.Policy) error {
	for _, rule := range policy.GetRules() {
		if err := f.AddRule(rule); err != nil {
			return err
		}
	}
	return nil
}

func (f *filterEvaluatorV2) EvalPackage(pkg *models.Package) (*FilterEvaluationResult, error) {
	policyInput, err := f.buildPolicyInput(pkg)
	if err != nil {
		return nil, err
	}

	serializedInput, err := f.serializePolicyInput(policyInput)
	if err != nil {
		return nil, err
	}

	for _, prog := range f.programs {
		out, _, err := prog.program.Eval(map[string]interface{}{
			policyInputVarRoot:     serializedInput,
			policyInputVarPackage:  serializedInput["package"],
			policyInputVarProject:  serializedInput["project"],
			policyInputVarManifest: serializedInput["manifest"],
		})
		if err != nil {
			logger.Warnf("CEL evaluator error: %s", err.Error())

			if f.ignoreError {
				continue
			}

			return nil, err
		}

		if (reflect.TypeOf(out).Kind() == reflect.Bool) &&
			(reflect.ValueOf(out).Bool()) {

			return &FilterEvaluationResult{
				match:   true,
				program: prog,
			}, nil
		}
	}

	return &FilterEvaluationResult{
		match: false,
	}, nil
}

// TODO: Fix this JSON round-trip problem by directly configuring CEL env to
// work with Protobuf messages
func (f *filterEvaluatorV2) serializePolicyInput(pi *policyv1.Input) (map[string]interface{}, error) {
	var ret map[string]interface{}

	data, err := protojson.Marshal(pi)
	if err != nil {
		return ret, err
	}

	logger.Debugf("Serialized policy input: %s", data)

	err = json.Unmarshal(data, &ret)
	if err != nil {
		return ret, err
	}

	return ret, nil
}

func (f *filterEvaluatorV2) buildPolicyInput(pkg *models.Package) (*policyv1.Input, error) {
	// Check if we have insights v2 data
	if pkg.InsightsV2 == nil {
		return nil, fmt.Errorf("package does not have insights v2 data required for policy evaluation")
	}

	insight := pkg.InsightsV2

	// Build the policy input
	policyInput := &policyv1.Input{
		Package: &policyv1.Input_Package{
			Ecosystem: pkg.GetControlTowerSpecEcosystem(),
			Name:      pkg.GetName(),
			Version:   pkg.GetVersion(),
			Insight:   insight,
		},
	}

	// Add licenses
	licenses := make([]*packagev1.LicenseMeta, 0)
	licenses = append(licenses, insight.GetLicenses().GetLicenses()...)
	policyInput.Package.Licenses = licenses

	// Add projects
	projects := make([]*packagev1.ProjectInsight, 0)
	projects = append(projects, insight.GetProjectInsights()...)
	policyInput.Package.Projects = projects

	// Add vulnerabilities
	vulnerabilities := make([]*policyv1.Input_Vulnerability, 0)
	for _, vuln := range insight.GetVulnerabilities() {
		policyVuln := &policyv1.Input_Vulnerability{
			Id: vuln.GetId().GetValue(),
		}

		// Add CVE ID (find first CVE from aliases)
		for _, alias := range vuln.GetAliases() {
			if strings.HasPrefix(strings.ToUpper(alias.GetValue()), "CVE-") {
				policyVuln.CveId = alias.GetValue()
				break
			}
		}

		// Add severity and score from the first available severity
		if len(vuln.GetSeverities()) > 0 {
			sev := vuln.GetSeverities()[0]
			policyVuln.Severity = string(sev.GetRisk())
			if score := sev.GetScore(); score != "" {
				if val, err := strconv.ParseFloat(score, 32); err == nil {
					policyVuln.CvssScore = float32(val)
				}
			}
		}

		vulnerabilities = append(vulnerabilities, policyVuln)
	}
	policyInput.Package.Vulnerabilities = vulnerabilities

	// Add package attributes
	policyInput.Package.Attributes = &policyv1.Input_Package_Attributes{
		Direct: pkg.IsDirect(),
	}

	// Add manifest information if available
	if pkg.Manifest != nil {
		policyInput.Manifest = &policyv1.Input_PackageManifest{
			Path:      pkg.Manifest.GetDisplayPath(),
			Ecosystem: pkg.Manifest.GetControlTowerSpecEcosystem(),
		}
	}

	// Add project information if available
	// This would be populated with project-specific information
	// For now, we'll leave it as nil since it's about the consuming project
	// not the open source project publishing the package

	return policyInput, nil
}

func celFuncLicenseExpressionMatch() func(ref.Val, ref.Val) ref.Val {
	return func(lhs, rhs ref.Val) ref.Val {
		l, ok := lhs.(traits.Lister)
		if !ok {
			logger.Warnf("celFuncLicenseExpressionMatch: lhs is not a list")
			return types.Bool(false)
		}

		filterLicenseExp := fmt.Sprintf("%s", rhs)
		iter := l.Iterator()
		contains := false

		i := 0
		for {
			if contains {
				break
			}

			if iter.HasNext().Value() == false {
				break
			}

			str := l.Get(types.Int(i))
			extracted, err := spdxexp.ExtractLicenses(fmt.Sprintf("%s", str))
			if err != nil {
				logger.Errorf("error while extracting license exp: %v", err)
				break
			}

			satisfied, err := spdxexp.Satisfies(filterLicenseExp, extracted)
			if err != nil {
				logger.Errorf("error while checking license exp: %v", err)
				break
			}

			contains = satisfied
			i++
		}

		return types.Bool(contains)
	}
}