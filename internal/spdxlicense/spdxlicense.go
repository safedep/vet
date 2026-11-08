// Package spdxlicense is the one entry point of vet to the SPDX rules. It
// reads the license of a package as an SPDX license expression, compares two
// licenses, and checks a license against allow and deny lists.
//
// The rules are in github.com/safedep/dry/policy/spdxlicense. The pull
// request check of SafeDep Cloud uses the same package, so vet and the cloud
// policy decide a license in the same way. This package adds no rule. Other
// vet packages import this package and not dry, so that one package holds
// the SPDX dependency of vet.
package spdxlicense

import (
	dry "github.com/safedep/dry/policy/spdxlicense"
)

// Declared is the license of a package, from its declared license values.
type Declared = dry.Declared

// Policy holds an allow list and a deny list of the license control.
type Policy = dry.Policy

// Result is the verdict of a check, with the denied terms of a Denied
// verdict.
type Result = dry.Result

// Verdict is the result of a license check.
type Verdict = dry.Verdict

// The verdicts of a license check.
const (
	Pass       = dry.Pass
	Denied     = dry.Denied
	NotAllowed = dry.NotAllowed
	Unknown    = dry.Unknown
)

// The names of the license sets that an allow or a deny list of the vet
// config can hold. A list of the cloud policy cannot hold them.
const (
	SetOSIApproved      = dry.SetOSIApproved
	SetFSFLibre         = dry.SetFSFLibre
	SetOSIApprovedOrFSF = dry.SetOSIApprovedOrFSF
)

// Parse reads the declared license values of a package. The values join
// with AND. A package with no value has an unknown license.
func Parse(values []string) Declared { return dry.Parse(values) }

// ActiveID returns the active SPDX license id of v, in the case of the SPDX
// License List, or false when v is not one active id.
func ActiveID(v string) (string, bool) { return dry.ActiveID(v) }

// Equal reports whether two lists of declared license values name the same
// license, in their canonical form.
func Equal(a, b []string) bool { return dry.Equal(a, b) }

// NewPolicy checks each entry and expands the sets. An entry that is not an
// SPDX license id, an id WITH an exception, a LicenseRef or a set name is an
// error, so a typo cannot open the gate.
func NewPolicy(allow, deny []string) (*Policy, error) { return dry.NewPolicy(allow, deny) }

// Restricted reports that each choice of the license has a license that
// limits the use of the code, such as SSPL-1.0, BUSL-1.1 or CC-BY-NC-4.0.
func Restricted(d Declared) bool { return dry.Restricted(d) }

// ListVersion names the SPDX License List that decides a license check.
func ListVersion() string { return dry.ListVersion() }
