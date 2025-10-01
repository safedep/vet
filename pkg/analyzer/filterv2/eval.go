package filterv2

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"
	vulnerabilityv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/vulnerability/v1"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"

	"github.com/github/go-spdx/v2/spdxexp"
)

const (
	// Policy Input v2 variable names for CEL expressions
	policyInputVarRoot     = "_"
	policyInputVarPackage  = "pkg" // Can't use "package" as it's a reserved keyword
	policyInputVarProject  = "project"
	policyInputVarManifest = "manifest"

	// Soft limit to start with till we have benchmarks to determine the performance
	// impact as rules starts to grow
	filterEvalMaxRules = 150
)

var errMaxFilter = errors.New("max filter limit has been reached")

// Evaluator interface for the new policy system using Insights v2 data model
type Evaluator interface {
	// AddPolicy adds a policy to the evaluator
	AddPolicy(policy *policyv1.Policy) error

	// EvaluatePackage evaluates a package against the policies
	EvaluatePackage(pkg *models.Package) (*FilterEvaluationResult, error)
}

type filterEvaluator struct {
	name        string
	env         *cel.Env
	programs    []*FilterProgram
	ignoreError bool
}

var _ Evaluator = (*filterEvaluator)(nil)

// NewEvaluator creates a new CEL evaluator for the policy system v2
func NewEvaluator(name string, ignoreError bool) (*filterEvaluator, error) {
	env, err := cel.NewEnv(
		cel.Macros(cel.StandardMacros...),
		cel.EnableMacroCallTracking(),
		ext.Strings(),
		ext.Encoders(),
		ext.Math(),
		ext.Lists(),
		ext.Sets(),
		ext.Protos(),

		// Register protobuf message types for direct usage
		// While this will avoid JSON round-trip problem, it will increase the
		// maintenance overhead because we need to manually register types.
		cel.Types(&policyv1.Input{}),
		cel.Types(&policyv1.Input_Package{}),
		cel.Types(&policyv1.Input_Vulnerability{}),
		cel.Types(&policyv1.Input_PackageManifest{}),
		cel.Types(&packagev1.PackageVersionInsight{}),
		cel.Types(&packagev1.ProjectInsight{}),
		cel.Types(&packagev1.LicenseMeta{}),

		// Input var declarations using proto message types
		// This is required only for the root object types.
		cel.Variable(policyInputVarRoot, cel.ObjectType("safedep.messages.policy.v1.Input")),
		cel.Variable(policyInputVarPackage, cel.ObjectType("safedep.messages.policy.v1.Input.Package")),
		cel.Variable(policyInputVarProject, cel.ObjectType("safedep.messages.policy.v1.Input.Project")),
		cel.Variable(policyInputVarManifest, cel.ObjectType("safedep.messages.policy.v1.Input.PackageManifest")),

		// Declare enum constants for better UX
		cel.Variable("ProjectSourceType", cel.MapType(cel.StringType, cel.IntType)),
		cel.Variable("Ecosystem", cel.MapType(cel.StringType, cel.IntType)),

		// Custom function declarations
		cel.Function("contains_license",
			cel.MemberOverload("list_string_contains_license_string",
				[]*cel.Type{cel.ListType(cel.StringType), cel.StringType}, cel.BoolType,
				cel.BinaryBinding(celFuncLicenseExpressionMatch()))),

		// More custom functions goes here
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	return &filterEvaluator{
		name:        name,
		env:         env,
		programs:    []*FilterProgram{},
		ignoreError: ignoreError,
	}, nil
}

func (f *filterEvaluator) AddRule(policy *policyv1.Policy, rule *policyv1.Rule) error {
	if len(f.programs) >= filterEvalMaxRules {
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
		policy:  policy,
		program: prog,
	})

	return nil
}

func (f *filterEvaluator) AddPolicy(policy *policyv1.Policy) error {
	for _, rule := range policy.GetRules() {
		if err := f.AddRule(policy, rule); err != nil {
			return err
		}
	}

	return nil
}

func (f *filterEvaluator) EvaluatePackage(pkg *models.Package) (*FilterEvaluationResult, error) {
	policyInput, err := f.buildPolicyInput(pkg)
	if err != nil {
		return nil, err
	}

	// Get enum constants
	enumConstants := getEnumConstantsMap()

	// Create evaluation input map with protobuf messages directly and enum constants
	evalInputMap := map[string]any{
		policyInputVarRoot:     policyInput,
		policyInputVarPackage:  policyInput.GetPackage(),
		policyInputVarProject:  policyInput.GetProject(),
		policyInputVarManifest: policyInput.GetManifest(),
		"ProjectSourceType":    enumConstants["ProjectSourceType"],
		"Ecosystem":            enumConstants["Ecosystem"],
	}

	for _, prog := range f.programs {
		out, _, err := prog.program.Eval(evalInputMap)
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

func (f *filterEvaluator) buildPolicyInput(pkg *models.Package) (*policyv1.Input, error) {
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

	// Add open source projects associated with the package
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

			// Transform into human readable severity as per contract
			// https://buf.build/safedep/api/docs/main:safedep.messages.policy.v1#safedep.messages.policy.v1.Input.Vulnerability
			switch sev.GetRisk() {
			case vulnerabilityv1.Severity_RISK_CRITICAL:
				policyVuln.Severity = "CRITICAL"
			case vulnerabilityv1.Severity_RISK_HIGH:
				policyVuln.Severity = "HIGH"
			case vulnerabilityv1.Severity_RISK_MEDIUM:
				policyVuln.Severity = "MEDIUM"
			case vulnerabilityv1.Severity_RISK_LOW:
				policyVuln.Severity = "LOW"
			case vulnerabilityv1.Severity_RISK_UNSPECIFIED:
				policyVuln.Severity = "UNSPECIFIED"
			}

			if score := sev.GetScore(); score != "" {
				if val, err := strconv.ParseFloat(score, 32); err == nil {
					policyVuln.CvssScore = float32(val)
				}
			}
		}

		vulnerabilities = append(vulnerabilities, policyVuln)
	}

	// Add vulnerabilities to policy input
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
		for !contains {
			// Value is `any` which is why we are explicitly checking for false
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
