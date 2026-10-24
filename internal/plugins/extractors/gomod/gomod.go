// Package gomod wraps the Scalibr go.mod extractor. Scalibr adds the Go
// standard library as the stdlib package, at the toolchain version or else
// at the go directive version. The go directive is the lowest Go version
// that the module allows, not the toolchain that builds it, so vet keeps
// stdlib only when a toolchain directive names the toolchain. Scalibr gives
// the target of a replace directive in place of the module, and the
// wrapper records the module path that the code imports.
package gomod

import (
	"bytes"
	"context"
	"io"
	"regexp"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/inventory"
	"golang.org/x/mod/modfile"
)

var toolchainRe = regexp.MustCompile(`(?m)^\s*toolchain\s+go\S+`)

// Extractor is the Scalibr go.mod extractor with the stdlib rule.
type Extractor struct {
	filesystem.Extractor
}

// New returns the extractor. It keeps the Scalibr name, so it replaces the
// upstream extractor.
func New() (*Extractor, error) {
	e, err := gomod.New(&cpb.PluginConfig{})
	if err != nil {
		return nil, err
	}
	return &Extractor{Extractor: e}, nil
}

// Extract runs the Scalibr extractor, and drops stdlib when the file has no
// toolchain directive.
func (e *Extractor) Extract(ctx context.Context, in *filesystem.ScanInput) (inventory.Inventory, error) {
	b, err := io.ReadAll(in.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}
	up := *in
	up.Reader = bytes.NewReader(b)
	inv, err := e.Extractor.Extract(ctx, &up)
	if err != nil {
		return inv, err
	}
	markReplaced(b, inv.Packages)
	if toolchainRe.Match(b) {
		return inv, nil
	}
	pkgs := inv.Packages[:0]
	for _, p := range inv.Packages {
		if !isStdlib(p) {
			pkgs = append(pkgs, p)
		}
	}
	inv.Packages = pkgs
	return inv, nil
}

// Replaced is the metadata of the target of a replace directive.
type Replaced struct{ path string }

// Replaces returns the module path that the code imports.
func (r Replaced) Replaces() string { return r.path }

// IsProtoable marks Replaced as Scalibr metadata.
func (Replaced) IsProtoable() {}

// markReplaced gives each target of a replace directive, at its line, the
// path of the module that it replaces. A file that does not parse marks
// nothing: Scalibr reports its error.
func markReplaced(data []byte, pkgs []*extractor.Package) {
	f, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return
	}
	for _, r := range f.Replace {
		if r.New.Version == "" {
			continue
		}
		for _, p := range pkgs {
			if p.Metadata == nil && p.Name == r.New.Path && p.Version == strings.TrimPrefix(r.New.Version, "v") && lineOf(p) == r.Syntax.Start.Line {
				p.Metadata = Replaced{path: r.Old.Path}
			}
		}
	}
}

func lineOf(p *extractor.Package) int {
	if loc := p.Location.Descriptor; loc != nil && loc.File != nil {
		return loc.File.LineNumber
	}
	return 0
}

func isStdlib(p *extractor.Package) bool { return p.Name == "stdlib" }
