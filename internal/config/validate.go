package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/safedep/vet/v2/internal/weburl"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// Validate checks every value of the effective config. Each error names the
// key, the bad value, the layer it came from and the allowed values.
func (l *Loaded) Validate() error {
	c := l.Config
	var errs []error
	check := func(key, value string, ok bool, allowed string) {
		if ok {
			return
		}
		errs = append(errs, errors.New(badValue(key, allowed, value, l.Origins.Of(key).String())))
	}

	check("output.mode", c.Output.Mode, slices.Contains([]string{"auto", "rich", "plain", "agent"}, c.Output.Mode), "must be auto, rich, plain or agent")
	check("output.color", c.Output.Color, slices.Contains([]string{"auto", "always", "never"}, c.Output.Color), "must be auto, always or never")
	check("scan.concurrency", fmt.Sprint(c.Scan.Concurrency), c.Scan.Concurrency >= 1 && c.Scan.Concurrency <= 256, "must be a number from 1 to 256")

	if c.Scan.Packages != "" {
		check("scan.packages", c.Scan.Packages, slices.Contains(model.PackagesValues, model.Packages(c.Scan.Packages)), "must be declared, installed or all")
	}

	if c.Policy.FailOn != "" {
		_, err := report.ParseFailOn(c.Policy.FailOn)
		check("policy.fail_on", c.Policy.FailOn, err == nil, "must be attacks, critical, high, medium, low or info")
	}

	for key, d := range map[string]Duration{
		"state.continue_within":       c.State.ContinueWithin,
		"state.retention.interrupted": c.State.Retention.Interrupted,
		"cache.ttl":                   c.Cache.TTL,
	} {
		_, err := d.Value()
		check(key, string(d), err == nil, "must be a duration such as 24h or 7d")
	}

	_, err := c.State.Retention.MaxSize.Bytes()
	check("state.retention.max_size", string(c.State.Retention.MaxSize), err == nil, "must be a size such as 500MB or 2GB")
	check("state.retention.per_target", fmt.Sprint(c.State.Retention.PerTarget), c.State.Retention.PerTarget >= 1, "must be 1 or more")

	for key, u := range map[string]string{
		"cloud.endpoints.api":       c.Cloud.Endpoints.API,
		"cloud.endpoints.community": c.Cloud.Endpoints.Community,
		"github.api_url":            c.GitHub.APIURL,
	} {
		check(key, u, weburl.Valid(u), "must be an http or https URL")
	}

	slices.SortFunc(errs, func(a, b error) int { return strings.Compare(a.Error(), b.Error()) })
	if len(errs) == 0 {
		return nil
	}
	msg := errors.Join(errs...).Error()
	return newError(CodeInvalid, msg, "Fix the value in its layer, then run vet config validate.")
}

// ValidateStrict is Validate plus an error for each unknown key of the file,
// for "vet config validate" in CI.
func (l *Loaded) ValidateStrict() error {
	if err := l.Validate(); err != nil {
		return err
	}
	if len(l.UnknownKeys) == 0 {
		return nil
	}
	var lines []string
	for _, k := range l.UnknownKeys {
		line := fmt.Sprintf("%s: unknown key in %s", k, l.File)
		if s := suggestKey(k); s != "" {
			line += fmt.Sprintf(". Did you mean %s?", s)
		}
		lines = append(lines, line)
	}
	return newError(CodeUnknownKey, strings.Join(lines, "\n"), "Remove or rename the unknown keys.")
}
