// Package sinks lists the report formats. One list serves -o FORMAT and
// --report FORMAT=PATH, and the format name is the sink name.
package sinks

import (
	"fmt"
	"slices"
	"strings"

	"github.com/safedep/dry/usefulerror"

	cloudreport "github.com/safedep/vet/v2/internal/plugins/cloud/report"
	"github.com/safedep/vet/v2/internal/plugins/sinks/cyclonedx"
	"github.com/safedep/vet/v2/internal/plugins/sinks/json"
	"github.com/safedep/vet/v2/internal/plugins/sinks/jsonl"
	"github.com/safedep/vet/v2/internal/plugins/sinks/markdown"
	"github.com/safedep/vet/v2/internal/plugins/sinks/plain"
	"github.com/safedep/vet/v2/internal/plugins/sinks/sarif"
	"github.com/safedep/vet/v2/internal/plugins/sinks/table"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/plugin"
)

// CodeOutput is the error code of a bad -o or --report value. The command
// exits with code 2.
const CodeOutput = "usage_output"

// Spec is one report format.
type Spec struct {
	Name        string
	Description string
	New         plugin.Factory[plugin.Sink]
}

// Checker is optional. A sink that implements it can refuse to run, before
// the scan starts. The SafeDep Cloud stub uses it.
type Checker interface {
	Check() error
}

// Registry is a list of formats, sorted by name.
type Registry []Spec

// Builtin returns the built-in formats.
func Builtin() Registry {
	return Registry{
		{Name: cloudreport.Name, Description: "the report for SafeDep Cloud (not available yet)", New: cloudreport.New},
		{Name: cyclonedx.Name, Description: "a CycloneDX 1.6 BOM of the packages and their vulnerabilities", New: cyclonedx.New},
		{Name: json.Name, Description: "the report as one JSON document", New: json.New},
		{Name: jsonl.Name, Description: "one report record on each line, as JSON", New: jsonl.New},
		{Name: markdown.Name, Description: "the counts and the findings, for a pull request comment", New: markdown.New},
		{Name: plain.Name, Description: "one finding on each line, with tab separated fields", New: plain.New},
		{Name: sarif.Name, Description: "SARIF 2.1.0, for code scanning", New: sarif.New},
		{Name: table.Name, Description: "the count cards and the most severe findings", New: table.New},
	}
}

// Formats returns the format names.
func (r Registry) Formats() []string {
	out := make([]string, 0, len(r))
	for _, s := range r {
		out = append(out, s.Name)
	}
	return out
}

// New builds the sink of a format with its options.
func (r Registry) New(format string, cfg plugin.Config) (plugin.Sink, error) {
	i := slices.IndexFunc(r, func(s Spec) bool { return s.Name == format })
	if i < 0 {
		return nil, r.usage(fmt.Sprintf("unknown format %q", format))
	}
	if cfg == nil {
		cfg = plugin.MapConfig(nil)
	}
	s, err := r[i].New(cfg)
	if err != nil {
		return nil, fmt.Errorf("plugins.%s.options: %w", format, err)
	}
	if c, ok := s.(Checker); ok {
		if err := c.Check(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Destination is a format and a path. An empty path is stdout.
type Destination struct {
	Format string
	Path   string
}

// Destinations checks -o and the --report values. It returns the stdout
// destination first. An empty -o picks the default format of the mode.
func (r Registry) Destinations(out string, reports []string, mode output.Mode) ([]Destination, error) {
	if out == "" {
		out = Default(mode)
	}
	if !slices.Contains(r.Formats(), out) {
		return nil, r.usage(fmt.Sprintf("-o: unknown format %q", out))
	}
	dests := []Destination{{Format: out}}
	seen := map[string]bool{}
	for _, v := range reports {
		format, path, ok := strings.Cut(v, "=")
		switch {
		case !ok || path == "":
			return nil, r.usage(fmt.Sprintf("--report %q: use FORMAT=PATH, for example json=vet.json", v))
		case !slices.Contains(r.Formats(), format):
			return nil, r.usage(fmt.Sprintf("--report %q: unknown format %q", v, format))
		case seen[path]:
			return nil, r.usage(fmt.Sprintf("--report %q: another --report writes %s", v, path))
		}
		seen[path] = true
		dests = append(dests, Destination{Format: format, Path: path})
	}
	return dests, nil
}

// Default returns the format of -o when the user sets none: table for
// rich mode, plain for plain mode and json for agent mode.
func Default(mode output.Mode) string {
	switch mode {
	case output.Agent:
		return "json"
	case output.Plain:
		return "plain"
	}
	return "table"
}

func (r Registry) usage(msg string) error {
	return usefulerror.NewUsefulError().
		WithCode(CodeOutput).
		WithHumanError(msg).
		WithHelp("Use one of these formats: " + strings.Join(r.Formats(), ", ") + ".").
		WithMsg(msg)
}
