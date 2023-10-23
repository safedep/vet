package remediations

import (
	"errors"
	"fmt"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/checks"
	jsonreportspec "github.com/safedep/vet/gen/jsonreport"
	"github.com/safedep/vet/gen/violations"
	"github.com/safedep/vet/pkg/models"
)

type RemediationGenerator interface {
	// We need the internal package model with insights so that we can propose remediation
	Advice(pkg *models.Package, violation *violations.Violation) (*jsonreportspec.RemediationAdvice, error)
}

type staticRemediationGenerator struct {
	// Nothing :)
}

func NewStaticRemediationGenerator() RemediationGenerator {
	return &staticRemediationGenerator{}
}

func (r *staticRemediationGenerator) Advice(pkg *models.Package,
	violation *violations.Violation) (*jsonreportspec.RemediationAdvice, error) {
	switch violation.CheckType {
	case checks.CheckType_CheckTypeVulnerability:
		return r.vulnerabilityRemediationGenerator(pkg)
	case checks.CheckType_CheckTypePopularity:
		return r.lowPopularityRemediationGenerator(pkg)
	}

	return nil, errors.New("no advice available")
}

func (r *staticRemediationGenerator) vulnerabilityRemediationGenerator(pkg *models.Package) (*jsonreportspec.RemediationAdvice, error) {
	insights := utils.SafelyGetValue(pkg.Insights)
	currentVersion := utils.SafelyGetValue(insights.PackageCurrentVersion)

	if !utils.IsEmptyString(currentVersion) && (pkg.Version != currentVersion) {
		return &jsonreportspec.RemediationAdvice{
			Type:                 jsonreportspec.RemediationAdviceType_UpgradePackage,
			TargetPackageName:    pkg.GetName(),
			TargetPackageVersion: currentVersion,
		}, nil
	}

	return nil, fmt.Errorf("target version not available for %s", pkg.ShortName())
}

func (r *staticRemediationGenerator) lowPopularityRemediationGenerator(pkg *models.Package) (*jsonreportspec.RemediationAdvice, error) {
	return &jsonreportspec.RemediationAdvice{
		Type: jsonreportspec.RemediationAdviceType_AlternatePopularPackage,
	}, nil
}
