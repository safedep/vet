package gomod

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"slices"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/vendormodules"
	"github.com/google/osv-scalibr/inventory"
)

// Vendor is the Scalibr vendor/modules.txt extractor. Scalibr gives the
// target of a replace line in place of the module, as for go.mod, so the
// wrapper records the module path that the code imports.
type Vendor struct {
	filesystem.Extractor
}

// NewVendor returns the extractor. It keeps the Scalibr name, so it
// replaces the upstream extractor.
func NewVendor() (*Vendor, error) {
	e, err := vendormodules.New(&cpb.PluginConfig{})
	if err != nil {
		return nil, err
	}
	return &Vendor{Extractor: e}, nil
}

// Extract runs the Scalibr extractor and marks the target of each replace
// line.
func (v *Vendor) Extract(ctx context.Context, in *filesystem.ScanInput) (inventory.Inventory, error) {
	b, err := io.ReadAll(in.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}
	up := *in
	up.Reader = bytes.NewReader(b)
	inv, err := v.Extractor.Extract(ctx, &up)
	if err != nil {
		return inv, err
	}
	markVendorReplaced(b, inv.Packages)
	return inv, nil
}

// markVendorReplaced gives each target of a module line such as
// "# old v1.0.0 => new v1.1.0" the path of the module that it replaces.
func markVendorReplaced(data []byte, pkgs []*extractor.Package) {
	s := bufio.NewScanner(bytes.NewReader(data))
	for line := 1; s.Scan(); line++ {
		text := strings.TrimSpace(s.Text())
		if !strings.HasPrefix(text, "# ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(text, "#"))
		arrow := slices.Index(fields, "=>")
		if arrow < 1 || len(fields)-arrow != 3 {
			continue
		}
		name, version := fields[arrow+1], strings.TrimPrefix(fields[arrow+2], "v")
		for _, p := range pkgs {
			if p.Metadata == nil && p.Name == name && p.Version == version && lineOf(p) == line {
				p.Metadata = Replaced{path: fields[0]}
			}
		}
	}
}
