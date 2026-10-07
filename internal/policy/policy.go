// Package policy is policy v2: the rules, the suppressions and the gate
// over vet's finding, package and manifest types (decisions D4).
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/safedep/dry/usefulerror"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/weburl"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// CodeInvalid is the error code of a policy file that does not load. The
// command exits with code 2.
const CodeInvalid = "policy_invalid"

// Version is the policy file version that vet reads.
const Version = 2

// Action is what a matching rule does.
type Action string

const (
	// ActionFail fails the gate.
	ActionFail Action = "fail"
	// ActionWarn marks the finding with the rule and does not fail the gate.
	ActionWarn Action = "warn"
)

// Rule is a condition and an action.
type Rule struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description,omitempty"`
	When        string `yaml:"when"`
	Action      Action `yaml:"action"`
	// Help tells the reader of a report what to do when the rule matches.
	Help string `yaml:"help,omitempty"`
	// Link is an http or https URL with more guidance, such as a page of
	// the security team.
	Link string `yaml:"link,omitempty"`
	// Severity is the severity of the finding that a package rule makes.
	// It is info when it is empty.
	Severity finding.Severity `yaml:"severity,omitempty"`

	expr   *Expr
	source string
}

// Source names the document of the rule.
func (r *Rule) Source() string { return r.source }

// Scope is what a rule runs on.
type Scope string

const (
	// ScopeFinding rules run on each finding.
	ScopeFinding Scope = "finding"
	// ScopePackage rules run on each package. A rule that reads package
	// and not finding has this scope.
	ScopePackage Scope = "package"
)

// Scope returns what the rule runs on.
func (r *Rule) Scope() Scope {
	if r.expr != nil && r.expr.reads[packageIdent] && !r.expr.reads["finding"] {
		return ScopePackage
	}
	return ScopeFinding
}

// Suppression hides the findings that match all of its selectors from the
// gate. A suppressed finding stays in the report.
type Suppression struct {
	// ID is a finding id.
	ID string `yaml:"id,omitempty"`
	// PURL matches the package of a finding. A PURL with no version
	// matches every version. A name with *, ? or [ is a glob, as in
	// pkg:golang/buf.build/gen/go/acme/*.
	PURL    string `yaml:"purl,omitempty"`
	Control string `yaml:"control,omitempty"`
	Reason  string `yaml:"reason"`
	// Expires is a date (2026-11-01) or a time (RFC 3339). The suppression
	// stops at that moment. A date means 00:00 UTC.
	Expires string `yaml:"expires,omitempty"`

	ref     string
	pkg     *model.PackagePattern
	expires *time.Time
}

// document is the file format.
type document struct {
	Version      int           `yaml:"version"`
	Rules        []Rule        `yaml:"rules"`
	Suppressions []Suppression `yaml:"suppressions"`
}

// Policy is the merged rules and suppressions of one or more documents.
type Policy struct {
	Sources      []string
	Rules        []Rule
	Suppressions []Suppression
}

// Load parses and merges the documents of a policy source.
func Load(docs []plugin.PolicyDoc) (*Policy, error) {
	out := &Policy{}
	var errs []error
	seen := map[string]string{}
	for _, d := range docs {
		p, err := parse(d.Name, d.Content)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, r := range p.Rules {
			if prev, dup := seen[r.ID]; dup {
				errs = append(errs, fmt.Errorf("%s: rule %q is also in %s", d.Name, r.ID, prev))
				continue
			}
			seen[r.ID] = d.Name
			out.Rules = append(out.Rules, r)
		}
		out.Sources = append(out.Sources, d.Name)
		out.Suppressions = append(out.Suppressions, p.Suppressions...)
	}
	if len(errs) > 0 {
		return nil, invalid(errors.Join(errs...))
	}
	return out, nil
}

// Parse parses and checks one policy document. name names it in errors.
func Parse(name string, data []byte) (*Policy, error) {
	p, err := parse(name, data)
	if err != nil {
		return nil, invalid(err)
	}
	return p, nil
}

func parse(name string, data []byte) (*Policy, error) {
	var doc document
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		return nil, yamlError(name, err)
	}
	var errs []error
	if doc.Version != Version {
		errs = append(errs, fmt.Errorf("version is %d: set version: %d", doc.Version, Version))
	}
	ids := map[string]bool{}
	for i := range doc.Rules {
		r := &doc.Rules[i]
		at := fmt.Sprintf("rules[%d]", i)
		switch {
		case r.ID == "":
			errs = append(errs, fmt.Errorf("%s: id is empty", at))
		case ids[r.ID]:
			errs = append(errs, fmt.Errorf("%s: id %q is not unique", at, r.ID))
		}
		ids[r.ID] = true
		if r.Action != ActionFail && r.Action != ActionWarn {
			errs = append(errs, fmt.Errorf("%s: action is %q: use fail or warn", at, r.Action))
		}
		if r.Severity != "" && !r.Severity.Valid() {
			errs = append(errs, fmt.Errorf("%s: severity is %q: use critical, high, medium, low or info", at, r.Severity))
		}
		if r.Link != "" && !weburl.Valid(r.Link) {
			errs = append(errs, fmt.Errorf("%s: link is %q: use an http or https URL", at, r.Link))
		}
		if r.When == "" {
			errs = append(errs, fmt.Errorf("%s: when is empty", at))
			continue
		}
		e, err := Compile(r.When)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: when: %w", at, err))
			continue
		}
		r.expr = e
	}
	for i := range doc.Suppressions {
		s := &doc.Suppressions[i]
		s.ref = fmt.Sprintf("%s#suppressions[%d]", name, i)
		if err := s.check(); err != nil {
			errs = append(errs, fmt.Errorf("suppressions[%d]: %w", i, err))
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%s: %w", name, errors.Join(errs...))
	}
	for i := range doc.Rules {
		doc.Rules[i].source = name
	}
	return &Policy{Sources: []string{name}, Rules: doc.Rules, Suppressions: doc.Suppressions}, nil
}

func (s *Suppression) check() error {
	var errs []error
	if s.ID == "" && s.PURL == "" && s.Control == "" {
		errs = append(errs, errors.New("set id, purl or control"))
	}
	if s.Reason == "" {
		errs = append(errs, errors.New("reason is empty"))
	}
	if s.PURL != "" {
		p, err := model.ParsePackagePattern(s.PURL)
		switch {
		case err != nil:
			errs = append(errs, err)
		case p.Glob() && s.Control == "":
			// A glob names many packages. With no control, it would also
			// hide an attack, such as malware in a package with a look-alike
			// name of the glob.
			errs = append(errs, fmt.Errorf("purl %q has a name glob: set control too", s.PURL))
		default:
			s.pkg = &p
		}
	}
	if s.Expires != "" {
		t, err := parseExpiry(s.Expires)
		if err != nil {
			errs = append(errs, err)
		} else {
			s.expires = &t
		}
	}
	return errors.Join(errs...)
}

func parseExpiry(v string) (time.Time, error) {
	if t, err := time.Parse(time.DateOnly, v); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("expires is %q: use a date such as 2026-11-01", v)
}

func invalid(err error) error {
	return usefulerror.NewUsefulError().
		WithCode(CodeInvalid).
		WithHumanError(err.Error()).
		WithHelp("Fix the policy file. vet policy validate FILE checks it.").
		WithMsg(err.Error())
}
