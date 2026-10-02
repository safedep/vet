package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/safedep/dry/usefulerror"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/plugin"
)

// CodeFailOn is the error code of a --fail-on value that is not a
// severity. The command exits with code 2.
const CodeFailOn = "usage_fail_on"

// Settings are the gate of a run.
type Settings struct {
	FailOn finding.Severity
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
		sev, err := finding.ParseSeverity(failOn)
		if err != nil {
			return Settings{}, usefulerror.NewUsefulError().WithCode(CodeFailOn).
				WithHumanError(err.Error()).
				WithHelp("Set --fail-on or policy.fail_on to critical, high, medium, low or info.").
				WithMsg(err.Error())
		}
		s.FailOn = sev
	}
	return s, nil
}

// NewFromSources loads the policy of the sources and returns its
// evaluator. With no source, the evaluator has the severity gate only.
func NewFromSources(ctx context.Context, failOn finding.Severity, now func() time.Time, sources ...plugin.PolicySource) (*Evaluator, error) {
	var docs []plugin.PolicyDoc
	for _, src := range sources {
		d, err := src.Policies(ctx)
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
	return NewEvaluator(p, Options{FailOn: failOn, Now: now}), nil
}
