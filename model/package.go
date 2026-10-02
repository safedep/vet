package model

import "time"

// Package is one package version that a manifest declares or resolves. The
// optional pointer fields hold the data of each data source. They are nil
// when the source did not answer.
type Package struct {
	ID     PackageID `json:"id"`
	Direct bool      `json:"direct"`
	Dev    bool      `json:"dev,omitempty"`
	Change Change    `json:"change,omitempty"`

	// PreviousVersion is the base version for an upgrade or a downgrade.
	PreviousVersion string `json:"previous_version,omitempty"`

	// Line is the line of the declaration in the manifest, when the extractor knows it.
	Line int `json:"line,omitempty"`

	// Resolved is the download URL that a lockfile records, when it records one.
	Resolved string `json:"resolved,omitempty"`

	// Integrity is the checksum that a lockfile records, when it records one.
	Integrity string `json:"integrity,omitempty"`

	Insight *Insight `json:"insight,omitempty"`
	// PreviousInsight is the Insights data of PreviousVersion, in pull
	// request mode. The controls that compare two versions read it.
	PreviousInsight *Insight         `json:"previous_insight,omitempty"`
	Malware         *MalwareAnalysis `json:"malware,omitempty"`
	Usage           *Usage           `json:"usage,omitempty"`
}

// Insight is the package data from SafeDep Insights v2.
type Insight struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	Licenses        []string        `json:"licenses,omitempty"`
	PublishedAt     *time.Time      `json:"published_at,omitempty"`
	Deprecated      bool            `json:"deprecated,omitempty"`
	Scorecard       *Scorecard      `json:"scorecard,omitempty"`
	SourceRepo      string          `json:"source_repo,omitempty"`
	Downloads       int64           `json:"downloads,omitempty"`
	LatestVersion   string          `json:"latest_version,omitempty"`
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
