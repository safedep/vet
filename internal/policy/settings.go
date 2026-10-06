package policy

import (
	"context"
	"errors"
	"fmt"

	"github.com/safedep/dry/usefulerror"

	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// CodeFailOn is the error code of a --fail-on value that is not a
// --fail-on value. The command exits with code 2.
const CodeFailOn = "usage_fail_on"

// Settings are the gate of a run.
type Settings struct {
	FailOn report.FailOn
	// File is the policy file, or "".
	File string
}

// ResolveSettings applies the --fail-on and --policy flags over the
// policy.fail_on and policy.file config keys. A flag wins. Both empty
// means report only, with no gate (decisions D3).
func ResolveSettings(failOnFlag, policyFlag string, cfg config.PolicyConfig) (Settings, error) {
	s := Settings{File: cfg.File}
	if policyFlag != "" {
		s.File = policyFlag
	}
	failOn := cfg.FailOn
	if failOnFlag != "" {
		failOn = failOnFlag
	}
	if failOn != "" {
		t, err := report.ParseFailOn(failOn)
		if err != nil {
			return Settings{}, usefulerror.NewUsefulError().WithCode(CodeFailOn).
				WithHumanError(err.Error()).
				WithHelp("Set --fail-on or policy.fail_on to attacks, critical, high, medium, low or info.").
				WithMsg(err.Error())
		}
		s.FailOn = t
	}
	return s, nil
}

// NewFromSources loads the policy of the sources and returns its
// evaluator. With no source, the evaluator has the --fail-on value only.
func NewFromSources(ctx context.Context, o Options, sources ...plugin.PolicySource) (*Evaluator, error) {
	var docs []plugin.PolicyDoc
	var unavailable []string
	for _, src := range sources {
		d, err := src.Policies(ctx)
		if errors.Is(err, plugin.ErrUnavailable) {
			unavailable = append(unavailable, err.Error())
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("load policy: %w", err)
		}
		docs = append(docs, d...)
	}
	var p *Policy
	if len(docs) > 0 {
		var err error
		if p, err = Load(docs); err != nil {
			return nil, err
		}
	}
	e := NewEvaluator(p, o)
	e.unavailable = unavailable
	return e, nil
}
