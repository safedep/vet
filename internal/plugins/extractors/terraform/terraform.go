// Package terraform extracts the providers of a Terraform dependency lock
// file, .terraform.lock.hcl. Scalibr has no Terraform extractor (research
// report, section 3).
package terraform

import (
	"context"
	"fmt"
	"io"
	"path"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Name is the name of the extractor.
const Name = "terraform/lockfile"

// PURLType is the PURL type of a Terraform provider.
const PURLType = "terraform"

// Extractor reads .terraform.lock.hcl files.
type Extractor struct{}

// New returns the extractor.
func New() *Extractor { return &Extractor{} }

// Name returns the name of the extractor.
func (Extractor) Name() string { return Name }

// Version returns the version of the extractor.
func (Extractor) Version() int { return 0 }

// Requirements returns the capabilities that the extractor needs.
func (Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired selects .terraform.lock.hcl files.
func (Extractor) FileRequired(api filesystem.FileAPI) bool {
	return path.Base(api.Path()) == ".terraform.lock.hcl"
}

// Extract returns one package for each provider block. The package name is
// the provider address, for example registry.terraform.io/hashicorp/aws.
func (Extractor) Extract(_ context.Context, in *filesystem.ScanInput) (inventory.Inventory, error) {
	src, err := io.ReadAll(in.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}
	f, diags := hclparse.NewParser().ParseHCL(src, in.Path)
	if diags.HasErrors() {
		return inventory.Inventory{}, fmt.Errorf("parse %s: %s", in.Path, diags.Error())
	}
	body, ok := f.Body.(*hclsyntax.Body)
	if !ok {
		return inventory.Inventory{}, fmt.Errorf("parse %s: not native HCL syntax", in.Path)
	}

	var pkgs []*extractor.Package
	for _, block := range body.Blocks {
		if block.Type != "provider" || len(block.Labels) == 0 {
			continue
		}
		version := ""
		if attr, ok := block.Body.Attributes["version"]; ok {
			v, diags := attr.Expr.Value(nil)
			if diags.HasErrors() || !v.IsKnown() || v.Type() != cty.String {
				return inventory.Inventory{}, fmt.Errorf("parse %s: provider %s: bad version", in.Path, block.Labels[0])
			}
			version = v.AsString()
		}
		pkgs = append(pkgs, &extractor.Package{
			Name:     block.Labels[0],
			Version:  version,
			PURLType: PURLType,
			Location: extractor.LocationFromPathAndLine(in.Path, block.DefRange().Start.Line),
		})
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

var _ filesystem.Extractor = Extractor{}
