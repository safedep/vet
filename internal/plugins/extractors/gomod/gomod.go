// Package gomod wraps the Scalibr go.mod extractor. Scalibr adds the Go
// standard library as the stdlib package, at the toolchain version or else
// at the go directive version. The go directive is the lowest Go version
// that the module allows, not the toolchain that builds it, so vet keeps
// stdlib only when a toolchain directive names the toolchain.
package gomod

import (
	"bytes"
	"context"
	"io"
	"regexp"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/inventory"
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
	if err != nil || toolchainRe.Match(b) {
		return inv, err
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

func isStdlib(p *extractor.Package) bool { return p.Name == "stdlib" }
