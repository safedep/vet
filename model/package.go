package model

import (
	"cmp"
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
}
