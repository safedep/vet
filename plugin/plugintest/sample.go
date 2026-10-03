package plugintest

import (
	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// SampleReport returns a small fixed report: one npm lockfile with two
// packages, one finding of each subject kind that applies, an inventory item
// and a diagnostic. Sink tests render it.
func SampleReport() *MemState {
	evil := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "evil-colors", Version: "1.4.1"}, Direct: true, Line: 42}
	pad := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "left-pad", Version: "1.3.0"}}
	m := &model.Manifest{
		ID: "m-1", Path: "package-lock.json", Ecosystem: model.EcosystemNpm, Kind: model.ManifestKindLockfile,
		Packages: []*model.Package{evil, pad},
	}

	malware := finding.ForPackage(finding.Meta{
		ControlID: "malware", Family: finding.FamilyMalware, Severity: finding.SeverityCritical,
		Title: "Malicious package", Description: "The package runs a postinstall script that reads ~/.npmrc.",
	}, m.Path, evil, finding.Key{})
	malware.Remediation = &finding.Remediation{Summary: "Remove evil-colors.", FixedVersion: "1.3.9"}
	malware.Evidence = []finding.Evidence{{Source: "malysis", Summary: "Verified malicious"}}

	workflow := finding.ForFile(finding.Meta{
		ControlID: "unpinned-action", Family: finding.FamilyWorkflow, Severity: finding.SeverityMedium,
		Title: "Third-party action is not pinned to a commit SHA",
	}, finding.Locus{Path: ".github/workflows/ci.yml", StartLine: 8, Snippet: "uses: tj-actions/changed-files@v44"},
		finding.Key{Discriminator: "tj-actions/changed-files"})

	suppressed := finding.ForPackage(finding.Meta{
		ControlID: "dependency-cooldown", Family: finding.FamilyCooldown, Severity: finding.SeverityHigh,
		Title: "Package version is inside the cooldown window",
	}, m.Path, pad, finding.Key{})
	suppressed.Suppression = &finding.Suppression{Reason: "Reviewed", Rule: "s-1"}

	return &MemState{
		ManifestList:  []*model.Manifest{m},
		FindingList:   []*finding.Finding{&malware, &workflow, &suppressed},
		InventoryList: []*report.InventoryItem{{Kind: report.InventoryMCPServer, Name: "filesystem", Client: "claude-code"}},
		CapabilityList: []*report.Capability{{
			ID: "crypto.md5", Description: "MD5 message digest", Product: "MD5", Service: "MD5",
			Tags:        []string{"cryptography", "hash", "weak"},
			Occurrences: []report.Occurrence{{File: "src/cache.py", Line: 3, Column: 9, Language: "python", Callee: "hashlib//md5"}},
		}, {
			ID: "openai.client", Description: "Creates a client of the OpenAI API.", Vendor: "OpenAI", Product: "OpenAI SDK",
			Service: "Chat Completions", Tags: []string{"ai", "llm"},
			Occurrences: []report.Occurrence{{File: "src/chat.py", Line: 12, Column: 5, Language: "python", Callee: "openai//OpenAI"}},
		}},
		DiagnosticList: []*report.Diagnostic{{Level: report.DiagnosticWarning, Code: "enrichment_unavailable", Component: "insights", Message: "2 packages have no data", Count: 2}},
	}
}
