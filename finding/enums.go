package finding

import (
	"fmt"
	"strings"
)

// Severity is a closed set of severities.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Severities returns every severity, from the most severe.
func Severities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
}

// Rank returns 4 for critical down to 0 for info, and -1 for an unknown value.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityInfo:
		return 0
	}
	return -1
}

// Valid reports whether the severity is in the closed set.
func (s Severity) Valid() bool { return s.Rank() >= 0 }

// Title returns the severity with a capital first letter, for example
// "High".
func (s Severity) Title() string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(string(s[:1])) + string(s[1:])
}

// AtLeast reports whether s is as severe as other or more severe.
func (s Severity) AtLeast(other Severity) bool { return s.Rank() >= other.Rank() }

// ParseSeverity parses a severity name, with any case.
func ParseSeverity(v string) (Severity, error) {
	s := Severity(strings.ToLower(strings.TrimSpace(v)))
	if !s.Valid() {
		return "", fmt.Errorf("unknown severity %q: use one of critical, high, medium, low, info", v)
	}
	return s, nil
}

// Confidence is a closed set of confidence levels.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Valid reports whether the confidence is in the closed set.
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		return true
	}
	return false
}

// Family groups controls for the report summary.
type Family string

const (
	FamilyMalware       Family = "malware"
	FamilyVulnerability Family = "vulnerability"
	FamilyCooldown      Family = "cooldown"
	FamilyWorkflow      Family = "workflow"
	FamilyLockfile      Family = "lockfile"
	FamilyAgentConfig   Family = "agent-config"
	FamilyAIBOM         Family = "ai-bom"
	FamilyLicense       Family = "license"
	FamilyHygiene       Family = "hygiene"
	FamilyReputation    Family = "reputation"
)

// Families returns every family.
func Families() []Family {
	return []Family{
		FamilyMalware, FamilyVulnerability, FamilyCooldown, FamilyWorkflow, FamilyLockfile,
		FamilyAgentConfig, FamilyAIBOM, FamilyLicense, FamilyHygiene, FamilyReputation,
	}
}

// Valid reports whether the family is in the closed set.
func (f Family) Valid() bool {
	for _, v := range Families() {
		if v == f {
			return true
		}
	}
	return false
}

// SubjectKind names the kind of a finding subject.
type SubjectKind string

const (
	SubjectPackage     SubjectKind = "package"
	SubjectFile        SubjectKind = "file"
	SubjectManifest    SubjectKind = "manifest"
	SubjectApplication SubjectKind = "application"
)
