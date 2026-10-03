// Package cyclonedx is the CycloneDX 1.6 format: a BOM of the packages of
// the scan, with their known vulnerabilities, and of the capabilities that
// the code signatures find (the xBOM).
package cyclonedx

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the format name.
const Name = "cyclonedx"

// Sink writes the cyclonedx format.
type Sink struct{}

// New builds the sink. It has no options.
func New(cfg plugin.Config) (plugin.Sink, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, err
	}
	return Sink{}, nil
}

// Write writes the BOM. The serial number comes from the scan id, so one
// scan always gives the same BOM.
func (Sink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	h := r.Header()
	bom := cdx.NewBOM()
	bom.SerialNumber = serial(h.Scan.ID)
	bom.Metadata = &cdx.Metadata{
		Timestamp: h.Scan.StartedAt.UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{Components: &[]cdx.Component{{
			Type: cdx.ComponentTypeApplication, Name: h.Tool.Name, Version: h.Tool.Version, Publisher: "SafeDep", BOMRef: toolRef,
		}}},
		Component: &cdx.Component{Type: cdx.ComponentTypeApplication, Name: h.Scan.Target, BOMRef: "target"},
	}
	var comps []cdx.Component
	var vulns []cdx.Vulnerability
	for rec, err := range r.Records(ctx) {
		if err != nil {
			return err
		}
		switch {
		case rec.Package != nil:
			comps = append(comps, component(rec.Package))
			vulns = append(vulns, vulnerabilities(rec.Package)...)
		case rec.Capability != nil:
			comps = append(comps, capabilityComponent(rec.Capability))
		}
	}
	bom.Components = &comps
	if len(vulns) > 0 {
		bom.Vulnerabilities = &vulns
	}
	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	enc.SetEscapeHTML(false)
	return enc.EncodeVersion(bom, cdx.SpecVersion1_6)
}

func component(p *report.PackageEntry) cdx.Component {
	c := cdx.Component{
		BOMRef: p.PURL, Type: cdx.ComponentTypeLibrary, Name: p.ID.Name, Version: p.ID.Version, PackageURL: p.PURL,
		Group: p.ID.Namespace,
	}
	scope := cdx.ScopeRequired
	if p.Dev {
		scope = cdx.ScopeOptional
	}
	c.Scope = scope
	if in := p.Insight; in != nil && len(in.Licenses) > 0 {
		var ls cdx.Licenses
		for _, l := range in.Licenses {
			ls = append(ls, cdx.LicenseChoice{License: &cdx.License{ID: l}})
		}
		c.Licenses = &ls
	}
	props := []cdx.Property{{Name: "safedep:direct", Value: strconv.FormatBool(p.Direct)}}
	if p.Malware != nil && p.Malware.Malicious {
		props = append(props, cdx.Property{Name: "safedep:malware", Value: strconv.FormatBool(p.Malware.Verified)})
	}
	c.Properties = &props
	return c
}

// toolRef is the BOM reference of vet, the tool that finds the evidence.
const toolRef = "vet"

// knownTags are the signature tags that become component properties, as in
// vet v1.
var knownTags = []string{"ai", "cryptography", "encryption", "hash", "ml", "iaas", "paas", "saas"}

// capabilityComponent describes a capability as vet v1 did: the reference is
// xbom:<signature id>, and the evidence is the source code analysis with
// each matched call.
func capabilityComponent(c *report.Capability) cdx.Component {
	occurrences := make([]cdx.EvidenceOccurrence, 0, len(c.Occurrences))
	for _, o := range c.Occurrences {
		occ := cdx.EvidenceOccurrence{Location: o.File, AdditionalContext: o.Callee}
		if o.Line > 0 {
			occ.Line = &o.Line
		}
		if o.Column > 0 {
			occ.Offset = &o.Column
		}
		occurrences = append(occurrences, occ)
	}
	confidence := float32(1)
	var props []cdx.Property
	for _, tag := range knownTags {
		if c.HasTag(tag) {
			props = append(props, cdx.Property{Name: tag, Value: "true"})
		}
	}
	if c.Change != "" {
		props = append(props, cdx.Property{Name: "safedep:change", Value: string(c.Change)})
	}
	comp := cdx.Component{
		BOMRef: "xbom:" + c.ID, Type: cdx.ComponentTypeLibrary, Name: capabilityName(c), Description: c.Description,
		Publisher: c.Vendor,
		Evidence: &cdx.Evidence{
			Identity: &cdx.EvidenceIdentityChoice{Identities: &[]cdx.EvidenceIdentity{{
				Field:   cdx.EvidenceIdentityFieldTypeName,
				Methods: &[]cdx.EvidenceIdentityMethod{{Technique: cdx.EvidenceIdentityTechniqueSourceCodeAnalysis, Confidence: &confidence}},
				Tools:   &[]cdx.BOMReference{toolRef},
			}}},
			Occurrences: &occurrences,
		},
	}
	if c.Vendor != "" {
		comp.Manufacturer = &cdx.OrganizationalEntity{Name: c.Vendor}
	}
	if len(props) > 0 {
		comp.Properties = &props
	}
	return comp
}

func capabilityName(c *report.Capability) string {
	switch {
	case c.Product != "" && c.Service != "":
		return c.Product + " - " + c.Service
	case c.Product != "":
		return c.Product
	}
	return c.ID
}

func vulnerabilities(p *report.PackageEntry) []cdx.Vulnerability {
	if p.Insight == nil {
		return nil
	}
	out := make([]cdx.Vulnerability, 0, len(p.Insight.Vulnerabilities))
	for _, v := range p.Insight.Vulnerabilities {
		out = append(out, vulnerability(p, v))
	}
	return out
}

func vulnerability(p *report.PackageEntry, v model.Vulnerability) cdx.Vulnerability {
	cv := cdx.Vulnerability{
		BOMRef:      v.ID + "/" + p.PURL,
		ID:          v.ID,
		Description: v.Summary,
		Source:      &cdx.Source{Name: "OSV", URL: "https://osv.dev/vulnerability/" + v.ID},
		Affects:     &[]cdx.Affects{{Ref: p.PURL}},
	}
	rating := cdx.VulnerabilityRating{Severity: cdx.Severity(v.Severity)}
	if v.CVSS > 0 {
		score := v.CVSS
		rating.Score = &score
	}
	if v.Severity != "" || v.CVSS > 0 {
		cv.Ratings = &[]cdx.VulnerabilityRating{rating}
	}
	if len(v.Aliases) > 0 {
		var refs []cdx.VulnerabilityReference
		for _, a := range v.Aliases {
			refs = append(refs, cdx.VulnerabilityReference{ID: a})
		}
		cv.References = &refs
	}
	return cv
}

// serial returns a URN UUID (version 5 form) from the scan id.
func serial(scanID string) string {
	h := sha256.Sum256([]byte("vet-scan:" + scanID))
	h[6] = (h[6] & 0x0f) | 0x50
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}
