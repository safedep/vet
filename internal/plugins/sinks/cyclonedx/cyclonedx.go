// Package cyclonedx is the CycloneDX 1.7 format: a BOM of the packages of
// the scan, with their known vulnerabilities, and of the capabilities that
// the code signatures find (the xBOM). A cryptographic capability is a
// cryptographic asset, so the BOM is also a CBOM.
package cyclonedx

import (
	"cmp"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/safedep/vet/v2/internal/spdxlicense"
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
	if len(comps) > 0 {
		bom.Components = &comps
	}
	if len(vulns) > 0 {
		bom.Vulnerabilities = &vulns
	}
	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	enc.SetEscapeHTML(false)
	// Encode writes the BOM in the version of NewBOM. EncodeVersion would
	// convert the BOM, and its conversion turns a cryptographic asset into
	// an application in every version.
	return enc.Encode(bom)
}

func component(p *report.PackageEntry) cdx.Component {
	group, name := groupAndName(p.ID)
	c := cdx.Component{
		BOMRef: componentRef(p), Type: cdx.ComponentTypeLibrary,
		Group: group, Name: name, Version: p.ID.RawVersion(), PackageURL: p.PURL,
	}
	scope := cdx.ScopeRequired
	if p.Dev {
		scope = cdx.ScopeOptional
	}
	c.Scope = scope
	if in := p.Insight; in != nil {
		if ls := licenses(in.Licenses); len(ls) > 0 {
			c.Licenses = &ls
		}
	}
	props := []cdx.Property{{Name: "safedep:direct", Value: strconv.FormatBool(p.Direct)}}
	if p.Malware != nil && p.Malware.Malicious {
		props = append(props, cdx.Property{Name: "safedep:malware", Value: strconv.FormatBool(p.Malware.Verified)})
	}
	c.Properties = &props
	return c
}

// componentRef is the BOM reference of a package: its PURL, or its key
// when the name forms no PURL.
func componentRef(p *report.PackageEntry) string {
	return cmp.Or(p.PURL, string(p.ID.Key()))
}

// toolRef is the BOM reference of vet, the tool that finds the evidence.
const toolRef = "vet"

// capabilityComponent describes a capability: the reference is
// xbom:<signature id>, and the evidence is the source code analysis with
// each matched call. A cryptographic capability is a cryptographic asset
// with its crypto properties, so the BOM is also a CBOM.
func capabilityComponent(c *report.Capability) cdx.Component {
	occurrences := make([]cdx.EvidenceOccurrence, 0, len(c.Occurrences))
	for _, o := range c.Occurrences {
		occ := cdx.EvidenceOccurrence{Location: o.File, Symbol: o.Callee}
		if o.Line > 0 {
			occ.Line = &o.Line
		}
		if o.Column > 0 {
			occ.Offset = &o.Column
		}
		occurrences = append(occurrences, occ)
	}
	confidence := float32(1)
	props := make([]cdx.Property, 0, len(c.Tags)+1)
	for _, tag := range c.Tags {
		props = append(props, cdx.Property{Name: "safedep:tag", Value: tag})
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
	if crypto := cryptoProperties(c); crypto != nil {
		comp.Type, comp.Name, comp.CryptoProperties = cdx.ComponentTypeCryptographicAsset, cmp.Or(c.Service, c.ID), crypto
	}
	return comp
}

// cryptoPrimitives are the signature tags that name a CycloneDX crypto
// primitive.
var cryptoPrimitives = []cdx.CryptoPrimitive{
	cdx.CryptoPrimitiveHash, cdx.CryptoPrimitiveMAC, cdx.CryptoPrimitiveBlockCipher, cdx.CryptoPrimitiveStreamCipher,
	cdx.CryptoPrimitiveSignature, cdx.CryptoPrimitivePKE, cdx.CryptoPrimitiveKDF, cdx.CryptoPrimitiveKeyAgree,
	cdx.CryptoPrimitiveAE, cdx.CryptoPrimitiveDRBG, cdx.CryptoPrimitiveKEM, cdx.CryptoPrimitiveXOF,
}

// cryptoProperties returns the crypto properties of a capability with the
// cryptography tag, or nil. A protocol tag gives a protocol, a certificate
// tag a certificate, a token tag a token, and a primitive tag an algorithm
// of the family that the signature product names.
func cryptoProperties(c *report.Capability) *cdx.CryptoProperties {
	if !c.HasTag(report.TagCrypto) {
		return nil
	}
	switch {
	case c.HasTag("protocol"):
		kind := cdx.CryptoProtocolTypeOther
		for _, t := range []cdx.CryptoProtocolType{cdx.CryptoProtocolTypeTLS, cdx.CryptoProtocolTypeSSH} {
			if c.HasTag(string(t)) {
				kind = t
			}
		}
		return &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeProtocol, ProtocolProperties: &cdx.CryptoProtocolProperties{Type: kind}}
	case c.HasTag("certificate"):
		return &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeCertificate}
	case c.HasTag("token"):
		return &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{Type: cdx.RelatedCryptoMaterialTypeToken},
		}
	}
	primitive := cdx.CryptoPrimitiveUnknown
	for _, p := range cryptoPrimitives {
		if c.HasTag(string(p)) {
			primitive = p
			break
		}
	}
	return &cdx.CryptoProperties{
		AssetType:           cdx.CryptoAssetTypeAlgorithm,
		AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: primitive, AlgorithmFamily: family(c.Product)},
	}
}

func family(product string) string {
	if algorithmFamilies[product] {
		return product
	}
	return ""
}

// groupAndName splits the raw name into the CycloneDX group and name: the
// npm scope, the Maven group, the publisher of an editor extension, or the
// path before the last slash of a Go module, a Composer vendor, a GitHub
// action or a Terraform provider.
func groupAndName(id model.PackageVersion) (string, string) {
	name := id.RawName()
	switch id.Ecosystem() {
	case model.EcosystemNpm:
		if scope, rest, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
			return scope, rest
		}
	case model.EcosystemMaven:
		if i := strings.LastIndex(name, ":"); i >= 0 {
			return name[:i], name[i+1:]
		}
	case model.EcosystemVSCode, model.EcosystemOpenVSX:
		if publisher, rest, ok := strings.Cut(name, "."); ok {
			return publisher, rest
		}
	case model.EcosystemGo, model.EcosystemPackagist, model.EcosystemGitHubActions, model.EcosystemTerraformProvider:
		if i := strings.LastIndex(name, "/"); i >= 0 {
			return name[:i], name[i+1:]
		}
	}
	return "", name
}

// licenses returns the license choices of the declared licenses. An SPDX
// id is an id, and a name that SPDX does not know is a name. CycloneDX
// takes an SPDX expression, such as "Apache-2.0 OR MIT", only as the one
// choice, so the expression joins all the declared licenses with AND. A
// declared name that is not SPDX keeps each license a name.
func licenses(declared []string) cdx.Licenses {
	d := spdxlicense.Parse(declared)
	if !d.IDs && len(d.Unknown) == 0 && !d.None && d.Expression != "" {
		return cdx.Licenses{{Expression: d.Expression}}
	}
	var out cdx.Licenses
	for _, l := range declared {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if id, ok := spdxlicense.ActiveID(l); ok {
			out = append(out, cdx.LicenseChoice{License: &cdx.License{ID: id}})
			continue
		}
		out = append(out, cdx.LicenseChoice{License: &cdx.License{Name: l}})
	}
	return out
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
	ref := componentRef(p)
	cv := cdx.Vulnerability{
		BOMRef:      v.ID + "/" + ref,
		ID:          v.ID,
		Description: v.Summary,
		Source:      advisorySource(v.ID),
		Affects:     &[]cdx.Affects{{Ref: ref}},
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
			refs = append(refs, cdx.VulnerabilityReference{ID: a, Source: advisorySource(a)})
		}
		cv.References = &refs
	}
	return cv
}

// advisorySource returns the database that publishes an advisory id: NVD
// for a CVE, GitHub for a GHSA, and OSV for the rest.
func advisorySource(id string) *cdx.Source {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return &cdx.Source{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + id}
	case strings.HasPrefix(id, "GHSA-"):
		return &cdx.Source{Name: "GitHub", URL: "https://github.com/advisories/" + id}
	}
	return &cdx.Source{Name: "OSV", URL: "https://osv.dev/vulnerability/" + id}
}

// serial returns a URN UUID (version 5 form) from the scan id.
func serial(scanID string) string {
	h := sha256.Sum256([]byte("vet-scan:" + scanID))
	h[6] = (h[6] & 0x0f) | 0x50
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}
