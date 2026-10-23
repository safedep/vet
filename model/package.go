package model

import (
	"cmp"
	"slices"
	"time"
)

// Package is one package version that a manifest declares or resolves.
// Enrichment holds the data of each enricher. A field is nil when the
// enricher did not answer.
type Package struct {
	ID     PackageVersion `json:"id"`
	Direct bool           `json:"direct"`
	Dev    bool           `json:"dev,omitempty"`
	Change Change         `json:"change,omitempty"`

	// PreviousVersion is the base version for an upgrade or a downgrade.
	PreviousVersion string `json:"previous_version,omitempty"`

	// PreviousResolved and PreviousIntegrity are the base download URL and
	// checksum of a modified package: the same version from another source.
	PreviousResolved  string `json:"previous_resolved,omitempty"`
	PreviousIntegrity string `json:"previous_integrity,omitempty"`

	// Line is the line of the declaration in the manifest, when the extractor knows it.
	Line int `json:"line,omitempty"`

	// Resolved is the download URL that a lockfile records, when it records one.
	Resolved string `json:"resolved,omitempty"`

	// Integrity is the checksum that a lockfile records, when it records one.
	Integrity string `json:"integrity,omitempty"`

	// Declared is the place where the project sets the version of a package
	// that the manifest records but does not declare, as the
	// "packageManager" field of package.json for pnpm and the packages that
	// pnpm installs for itself. A fix edits that place.
	Declared *Declaration `json:"declared,omitempty"`

	// Local marks a package that the project builds from its own tree, such
	// as a workspace member or an editable install. It is not a registry
	// package, so vet does not look it up.
	Local bool `json:"local,omitempty"`

	Enrichment

	// PreviousInsight is the Insights data of PreviousVersion, in pull
	// request mode. The controls that compare two versions read it.
	PreviousInsight *Insight `json:"previous_insight,omitempty"`
}

// Enrichment holds the package data that the enrichers set. Each field
// belongs to one enricher. The engine, the scan file and the enrichment
// cache copy the fields through this struct. A new enricher adds its field
// here, and to Merge and Since.
type Enrichment struct {
	Insight *Insight         `json:"insight,omitempty"`
	Malware *MalwareAnalysis `json:"malware,omitempty"`
	Usage   *Usage           `json:"usage,omitempty"`
	Action  *ActionCommit    `json:"action,omitempty"`
}

// Empty reports whether no field is set.
func (e Enrichment) Empty() bool { return e == Enrichment{} }

// Merge returns e with each field that o sets.
func (e Enrichment) Merge(o Enrichment) Enrichment {
	return Enrichment{
		Insight: cmp.Or(o.Insight, e.Insight), Malware: cmp.Or(o.Malware, e.Malware),
		Usage: cmp.Or(o.Usage, e.Usage), Action: cmp.Or(o.Action, e.Action),
	}
}

// Since returns the fields of e that differ from before. They are the
// data that an enricher set.
func (e Enrichment) Since(before Enrichment) Enrichment {
	return Enrichment{
		Insight: changed(e.Insight, before.Insight), Malware: changed(e.Malware, before.Malware),
		Usage: changed(e.Usage, before.Usage), Action: changed(e.Action, before.Action),
	}
}

func changed[T any](now, was *T) *T {
	if now == was {
		return nil
	}
	return now
}

// ActionCommit is the GitHub data of a GitHub Actions package pinned to a
// commit. A nil value means that the check did not finish.
type ActionCommit struct {
	// Reachable reports that a branch or a tag of the repository contains
	// the commit.
	Reachable bool `json:"reachable"`
	// Tags are the tags that point to the commit.
	Tags []string `json:"tags,omitempty"`
	// Ref is the first branch or tag that vet found to contain the commit.
	Ref string `json:"ref,omitempty"`
}

// Checkable reports whether a registry can answer for the package: it has a
// version and it is not local.
func (p *Package) Checkable() bool { return p.ID.RawVersion() != "" && !p.Local }

// Insight is the package data from SafeDep Insights v2.
type Insight struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	Licenses        []string        `json:"licenses,omitempty"`
	// PublishedAt is the date that the registry published the version.
	PublishedAt *time.Time `json:"published_at,omitempty"`
	Deprecated  bool       `json:"deprecated,omitempty"`
	Scorecard   *Scorecard `json:"scorecard,omitempty"`
	SourceRepo  string     `json:"source_repo,omitempty"`
	// Downloads is the download count of the version. Zero means that
	// the registry gives no count.
	Downloads     int64  `json:"downloads,omitempty"`
	LatestVersion string `json:"latest_version,omitempty"`
	// FirstPublishedAt is the publish date of the first version of the
	// package.
	FirstPublishedAt *time.Time `json:"first_published_at,omitempty"`
	// Provenance reports a SLSA provenance attestation for the version.
	Provenance bool `json:"provenance,omitempty"`
	// Stars is the star count of the source repository.
	Stars int64 `json:"stars,omitempty"`
}

// Vulnerability is one advisory that affects the package version.
type Vulnerability struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	Severity string   `json:"severity,omitempty"`
	CVSS     float64  `json:"cvss,omitempty"`
	Fixed    []string `json:"fixed,omitempty"`
}

// Scorecard is the OpenSSF Scorecard result of the source repository.
type Scorecard struct {
	Score  float64            `json:"score"`
	Checks map[string]float64 `json:"checks,omitempty"`
}

// MalwareAnalysis is the verdict of SafeDep Malysis.
type MalwareAnalysis struct {
	Malicious  bool   `json:"malicious"`
	Verified   bool   `json:"verified"`
	Confidence string `json:"confidence,omitempty"`
	Summary    string `json:"summary,omitempty"`
	ReportURL  string `json:"report_url,omitempty"`
	AnalysisID string `json:"analysis_id,omitempty"`
}

// Usage is the code usage evidence for the package.
type Usage struct {
	Imported bool     `json:"imported"`
	Files    []string `json:"files,omitempty"`
	// Imports hold the first import of the package in each file of Files.
	Imports []ImportSite `json:"imports,omitempty"`
	// TestOnly marks a package that only test files import.
	TestOnly bool `json:"test_only,omitempty"`
	// Incomplete marks an analysis that its time budget stopped. A
	// missing import then proves nothing.
	Incomplete bool `json:"incomplete,omitempty"`
	// UnreadFiles marks a project with a source file of a language of the
	// package that the analysis could not read, parse or index whole.
	UnreadFiles bool `json:"unread_files,omitempty"`
	// NoSourceFiles marks a project with no source file that the analysis
	// parses in a language of the package.
	NoSourceFiles bool `json:"no_source_files,omitempty"`
	// DynamicImport marks a project that imports a module by a computed
	// name in a language of the package. A missing import then proves
	// nothing.
	DynamicImport bool `json:"dynamic_import,omitempty"`
	// Calls are the calls of the code into the package, at most 200.
	Calls []CallSite `json:"calls,omitempty"`
	// Dynamic are the dynamic sites of the files that import the package.
	Dynamic []DynamicSite `json:"dynamic,omitempty"`
	// Symbols are the symbol records of the vulnerabilities of an imported
	// package.
	Symbols []SymbolRecord `json:"symbols,omitempty"`
}

// SymbolRecord is what the symbol data says about one vulnerability of a
// package: the functions that hold the vulnerable code.
type SymbolRecord struct {
	// Advisory is the id of the vulnerability, as Insights names it.
	Advisory string `json:"advisory"`
	// Record is the id of the symbol record.
	Record string `json:"record"`
	// Coverage is exact when the list of fix sites is complete, and broad
	// when it can miss some.
	Coverage string `json:"coverage"`
	// Verified marks a record that its maintainers reviewed. Only an exact
	// and verified record can prove that the code calls no fix site.
	Verified bool `json:"verified,omitempty"`
	// Review is the review state of the record, as verified or unreviewed.
	Review string `json:"review,omitempty"`
	// Source names the symbol data, as vuln-symbols, and License the
	// license of the record.
	Source   string   `json:"source,omitempty"`
	License  string   `json:"license,omitempty"`
	FixSites []string `json:"fix_sites"`
	// Keys are the symbol keys of the fix sites in the call graph, as
	// golang.org//x//net//html//Render. A fix site with no key rule has
	// none.
	Keys []string `json:"keys,omitempty"`
	// Reach is what the call graph says about the fix sites, or nil when
	// vet did not search.
	Reach *FunctionReach `json:"reach,omitempty"`
}

// FunctionReach is the answer of the call graph for the fix sites of one
// record.
type FunctionReach struct {
	// Status is called, not-found or unknown. Not-found is no path in the
	// graph of the project and the dependency code that vet read. Only the
	// engine turns it into not called, because another dependency can
	// call the fix site.
	Status string `json:"status"`
	// Cause says why the status is unknown.
	Cause string `json:"cause,omitempty"`
	// Path is the call path from an entry point to a fix site.
	Path []PathHop `json:"path,omitempty"`
	// TestOnly marks a path that only a test reaches.
	TestOnly bool `json:"test_only,omitempty"`
}

// CoverageExact is the coverage of a record that names every fix site.
const CoverageExact = "exact"

// The statuses of a FunctionReach.
const (
	FunctionCalled   = "called"
	FunctionNotFound = "not-found"
	FunctionUnknown  = "unknown"
)

// HopHigh is the confidence of a call that the call graph resolves for
// sure, as a direct call.
const HopHigh = "high"

// WeakPath reports a call path with a call that the call graph only
// guesses, as a call by name or through an interface to each type that
// implements it. A real scan showed that such a path is often not a call.
func WeakPath(path []PathHop) bool {
	// The first hop is the entry point and has no call. A later hop with no
	// confidence is weak, so a call that the graph does not rate never
	// counts as high.
	return len(path) > 1 && slices.ContainsFunc(path[1:], func(h PathHop) bool { return h.Confidence != HopHigh })
}

// PathHop is one function of a call path, with the line of its call into
// the next hop. The first hop is the entry point and Root names its kind.
type PathHop struct {
	Function string `json:"function"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Root     string `json:"root,omitempty"`
	// Edge is the kind of the call into the hop, as direct or cha, and
	// Confidence is how sure the call graph is of it.
	Edge       string `json:"edge,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

// CallSite is one call of the code into a package. Callee is the call
// target with "//" between its parts, as golang.org//x//net//html//Render.
type CallSite struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Callee string `json:"callee"`
}

// DynamicSite is a line of a source file that the static analysis cannot
// follow, such as eval or an import by a computed name. Kind names it as
// safedep/code does.
type DynamicSite struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Kind string `json:"kind"`
}

// ImportSite is the line of a source file that imports a package.
type ImportSite struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// ProvableReach reports a package whose call paths can prove a finding:
// the project imports it, and it is not the standard library of Go. Any
// dependency can call another package or the standard library, through
// code that the scan did not read.
func (p *Package) ProvableReach() bool {
	return p.Usage != nil && p.Usage.Imported && !p.ID.GoStdlib()
}

// Declaration is the field of a project file that sets the version of a
// package, such as "packageManager" in package.json.
type Declaration struct {
	// Path is the file, relative to the scan target, with "/".
	Path string `json:"path"`
	// Line is the line of the field, or 0 when vet does not know it.
	Line  int    `json:"line,omitempty"`
	Field string `json:"field"`
	// Package is the name of the package that the field sets. The packages
	// that it installs share its declaration.
	Package string `json:"package"`
}
