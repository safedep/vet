package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/safedep/vet/pkg/reporter/templates"

	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
)

type HtmlReportingConfig struct {
	Path string // Output path for HTML file
}

type htmlReporter struct {
	config         HtmlReportingConfig
	manifests      []*models.PackageManifest
	analyzerEvents []*analyzer.AnalyzerEvent
}

// Helper function to get NVD link from CVE ID
func getNvdLinkFromCveID(cveID string) string {
	if cveID == "" {
		return ""
	}
	return fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID)
}

func NewHtmlReporter(config HtmlReportingConfig) (Reporter, error) {
	return &htmlReporter{
		config:         config,
		manifests:      []*models.PackageManifest{},
		analyzerEvents: []*analyzer.AnalyzerEvent{},
	}, nil
}

func (r *htmlReporter) Name() string {
	return "html"
}

func (r *htmlReporter) AddManifest(manifest *models.PackageManifest) {
	r.manifests = append(r.manifests, manifest)
}

func (r *htmlReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	r.analyzerEvents = append(r.analyzerEvents, event)
}

func (r *htmlReporter) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *htmlReporter) Finish() error {
	// Create the directory if it doesn't exist
	dir := filepath.Dir(r.config.Path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory for HTML report: %w", err)
		}
	}

	vulnCount := 0
	malwareCount := 0
	otherCount := 0

	// Count insights vulnerabilities
	insightVulnCount := 0
	insightMalwareCount := 0
	for _, manifest := range r.manifests {
		for _, pkg := range manifest.Packages {
			if pkg.Insights != nil && pkg.Insights.Vulnerabilities != nil {
				insightVulnCount += len(*pkg.Insights.Vulnerabilities)
			}
			if pkg.MalwareAnalysis != nil && (pkg.MalwareAnalysis.IsMalware || pkg.MalwareAnalysis.IsSuspicious) {
				insightMalwareCount++
			}
		}
	}

	// Count analyzer events
	for _, event := range r.analyzerEvents {
		if event.Filter != nil {
			switch event.Filter.CheckType {
			case 1: // Vulnerability
				vulnCount++
			case 2: // Malware
				malwareCount++
			default:
				otherCount++
			}
		}
	}

	// Prepare the data for the templ template
	data := templates.ReportData{
		GeneratedAt:       time.Now(),
		Manifests:         r.convertManifests(),
		Packages:          r.getPackages(),
		Vulnerabilities:   r.getVulnerabilities(),
		MalwareDetections: r.getMalwareDetections(),
		PackagePopularity: r.getPopularityInfo(),
		PolicyViolations:  r.convertPolicyViolations(),
		PackageCount:      r.getPackageCount(),
		VulnCount:         r.getVulnCount(),
		Ecosystems:        r.getEcosystems(),
	}

	// Render the template to file using our helper
	if err := WriteTemplToFile(templates.VetScanReport(data), r.config.Path); err != nil {
		return fmt.Errorf("failed to render templ template: %w", err)
	}

	fmt.Printf("🔗 HTML report generated at: %s\n", r.config.Path)
	return nil
}

// Helper methods to prepare data for the HTML template

func (r *htmlReporter) getEcosystems() []string {
	ecosystemsMap := make(map[string]bool)

	for _, manifest := range r.manifests {
		ecosystemsMap[string(manifest.Ecosystem)] = true
	}

	ecosystems := make([]string, 0, len(ecosystemsMap))
	for ecosystem := range ecosystemsMap {
		ecosystems = append(ecosystems, ecosystem)
	}

	return ecosystems
}

func (r *htmlReporter) getPackageCount() int {
	count := 0
	for _, manifest := range r.manifests {
		count += len(manifest.Packages)
	}
	return count
}

func (r *htmlReporter) convertManifests() []templates.Manifest {
	manifests := []templates.Manifest{}
	for _, m := range r.manifests {
		packages := []templates.Package{}
		for _, p := range m.Packages {
			packages = append(packages, templates.Package{
				Name:      p.Name,
				Version:   p.Version,
				Ecosystem: string(m.Ecosystem),
				VulnCount: 0, // Will be updated with vulnerability count
				Source:    string(m.Source.Type),
			})
		}

		manifests = append(manifests, templates.Manifest{
			Path:      m.Path,
			Ecosystem: string(m.Ecosystem),
			Packages:  packages,
		})
	}

	sort.Slice(manifests, func(i, j int) bool {
		return len(manifests[i].Packages) > len(manifests[j].Packages)
	})
	return manifests
}

func (r *htmlReporter) convertPolicyViolations() []templates.PolicyViolation {
	events := []templates.PolicyViolation{}

	for _, event := range r.analyzerEvents {
		if !event.IsFilterMatch() {
			continue
		}

		// Create a vulnerability entry for the policy violation
		policyViolation := templates.PolicyViolation{
			ID:         event.Package.Id(),
			PolicyName: event.Filter.GetName(),
			Description: fmt.Sprintf("%s \n\n %s \n\n The CEL expression is:  \n\n ```yaml\n%s\n```\n\n",
				event.Filter.GetSummary(),
				event.Filter.GetDescription(),
				event.Filter.GetValue(),
			),
			Solution:       getPolicyViolationSolution(event),
			PackageName:    event.Package.Name,
			PackageVersion: event.Package.Version,
		}

		events = append(events, policyViolation)
	}
	return events
}

func (r *htmlReporter) getVulnerabilities() []templates.Vulnerability {
	vulns := []templates.Vulnerability{}

	// First try to extract vulnerabilities from package insights (preferred method)
	for _, manifest := range r.manifests {
		for _, pkg := range manifest.Packages {
			if pkg.Insights == nil || pkg.Insights.Vulnerabilities == nil {
				continue
			}

			for i, vuln := range *pkg.Insights.Vulnerabilities {
				// Extract severity
				severity := "MEDIUM"
				if vuln.Severities != nil && len(*vuln.Severities) > 0 {
					sev := (*vuln.Severities)[0]
					if sev.Risk != nil {
						severity = string(*sev.Risk)
					}
				}

				// Extract CVE ID from aliases
				cveID := ""
				if vuln.Aliases != nil {
					for _, alias := range *vuln.Aliases {
						if strings.HasPrefix(alias, "CVE-") {
							cveID = alias
							break
						}
					}
				}

				// Generate ID
				vulnID := ""
				if vuln.Id != nil {
					vulnID = *vuln.Id
				} else {
					vulnID = fmt.Sprintf("VUL-%s-%s-%d", pkg.Name, pkg.Version, i+1)
				}

				// Description
				description := ""
				if vuln.Summary != nil {
					description = *vuln.Summary
				}

				// Add the vulnerability
				vulns = append(vulns, templates.Vulnerability{
					ID:          vulnID,
					Package:     pkg.Name,
					Version:     pkg.Version,
					Severity:    severity,
					Description: description,
					Link:        getNvdLinkFromCveID(cveID), // Use CVE ID as link if available
				})
			}
		}
	}

	// If no vulnerabilities found in insights, try analyzer events as fallback
	if len(vulns) == 0 {
		for _, event := range r.analyzerEvents {
			// Check if the filter is related to vulnerabilities
			if event.Filter != nil && event.Filter.CheckType == 1 { // CheckType_CheckTypeVulnerability is 1
				// Default to MEDIUM severity if not specified
				severity := "MEDIUM"

				// Extract CVE ID from references if available
				cveID := ""
				link := ""
				for _, ref := range event.Filter.References {
					if strings.HasPrefix(ref, "CVE-") {
						cveID = ref
						link = getNvdLinkFromCveID(cveID)
						break
					} else if strings.HasPrefix(ref, "http") {
						link = ref
					}
				}

				// Generate a unique ID since VulnID doesn't exist in the Filter struct
				vulnID := fmt.Sprintf("VUL-%s-%s-%d",
					event.Package.Name,
					event.Package.Version,
					len(vulns)+1)

				vulns = append(vulns, templates.Vulnerability{
					ID:          vulnID,
					Package:     event.Package.Name,
					Version:     event.Package.Version,
					Severity:    severity,
					Description: event.Filter.Description,
					Link:        link, // Use the extracted link
				})
			}
		}
	}

	severityRank := map[string]int{
		"CRITICAL": 0,
		"HIGH":     1,
		"MEDIUM":   2,
		"LOW":      3,
		"UNKNOWN":  4,
	}

	sort.Slice(vulns, func(i, j int) bool {
		rankI, okI := severityRank[strings.ToUpper(vulns[i].Severity)]
		rankJ, okJ := severityRank[strings.ToUpper(vulns[j].Severity)]
		if !okI {
			rankI = severityRank["UNKNOWN"]
		}
		if !okJ {
			rankJ = severityRank["UNKNOWN"]
		}
		return rankI < rankJ
	})

	return vulns
}

func (r *htmlReporter) getVulnCount() int {
	return len(r.getVulnerabilities())
}

func (r *htmlReporter) getPackages() []templates.Package {
	packages := []templates.Package{}
	vulnCountMap := make(map[string]int)

	// First count vulnerabilities per package
	for _, vuln := range r.getVulnerabilities() {
		key := vuln.Package + "@" + vuln.Version
		vulnCountMap[key]++
	}

	// Then create package info
	for _, manifest := range r.manifests {
		for _, pkg := range manifest.Packages {
			key := pkg.Name + "@" + pkg.Version

			// Check for vulnerabilities in package insights directly
			insightVulnCount := 0
			if pkg.Insights != nil && pkg.Insights.Vulnerabilities != nil {
				insightVulnCount = len(*pkg.Insights.Vulnerabilities)
			}

			// Use the larger count between insights and counted vulnerabilities
			vulnCount := max(insightVulnCount, vulnCountMap[key])

			packages = append(packages, templates.Package{
				Name:      pkg.Name,
				Version:   pkg.Version,
				Ecosystem: string(manifest.Ecosystem),
				VulnCount: vulnCount,
				Source:    string(manifest.Source.Type),
			})
		}
	}

	sort.Slice(packages, func(i, j int) bool {
		return packages[i].VulnCount > packages[j].VulnCount
	})

	return packages
}

func (r *htmlReporter) getMalwareDetections() []templates.MalwareDetection {
	malware := []templates.MalwareDetection{}

	for _, manifest := range r.manifests {
		for _, pkg := range manifest.Packages {
			if pkg.MalwareAnalysis != nil && (pkg.MalwareAnalysis.IsMalware || pkg.MalwareAnalysis.IsSuspicious) {
				malwareType := "Malware"
				if !pkg.MalwareAnalysis.IsMalware && pkg.MalwareAnalysis.IsSuspicious {
					malwareType = "Suspicious"
				}

				details := "Malicious package detected"
				if pkg.MalwareAnalysis.Report != nil && pkg.MalwareAnalysis.Report.GetInference() != nil {
					inference := pkg.MalwareAnalysis.Report.GetInference()
					if inference.GetSummary() != "" {
						details = inference.GetSummary()
					}
				}

				malware = append(malware, templates.MalwareDetection{
					Package: pkg.Name,
					Version: pkg.Version,
					Type:    malwareType,
					Source:  "Package Analysis",
					Details: details,
				})
			}
		}
	}

	// If no malware found in package insights, try analyzer events
	if len(malware) == 0 {
		for _, event := range r.analyzerEvents {
			// Filter for malware events - handle all events with malware check type
			if event.Filter != nil && event.Filter.CheckType == 2 { // CheckType_CheckTypeMalware is 2
				malwareType := "Malware"
				if event.Type == analyzer.ET_SuspiciousPackage {
					malwareType = "Suspicious"
				}

				// Add malware detection
				malware = append(malware, templates.MalwareDetection{
					Package: event.Package.Name,
					Version: event.Package.Version,
					Type:    malwareType,
					Source:  event.Source,
					Details: event.Filter.Description,
				})
				// Also check for other malware/suspicious indicators from other analyzer types
			} else if event.Type == analyzer.ET_SuspiciousPackage {
				malware = append(malware, templates.MalwareDetection{
					Package: event.Package.Name,
					Version: event.Package.Version,
					Type:    "Suspicious",
					Source:  event.Source,
					Details: fmt.Sprintf("%v", event.Message),
				})
			} else if event.Type == analyzer.ET_LockfilePoisoningSignal {
				malware = append(malware, templates.MalwareDetection{
					Package: event.Package.Name,
					Version: event.Package.Version,
					Type:    "Lockfile Poisoning",
					Source:  event.Source,
					Details: fmt.Sprintf("%v", event.Message),
				})
			}
		}
	}

	typeRank := map[string]int{
		"Malware":            0,
		"Suspicious":         1,
		"Lockfile Poisoning": 2,
	}

	sort.Slice(malware, func(i, j int) bool {
		rankI, okI := typeRank[malware[i].Type]
		rankJ, okJ := typeRank[malware[j].Type]
		if !okI {
			rankI = 99 // unknown types go last
		}
		if !okJ {
			rankJ = 99
		}
		return rankI < rankJ
	})
	return malware
}

func (r *htmlReporter) getPopularityInfo() []templates.PopularityMetric {
	popularity := []templates.PopularityMetric{}

	// Limit to maximum 1000 packages to avoid memory issues
	packageCount := 0
	packageLimit := 1000

	for _, manifest := range r.manifests {
		for _, pkg := range manifest.Packages {
			// Check if we've hit our limit
			packageCount++
			if packageCount > packageLimit {
				return popularity
			}

			lastUpdated := ""
			stars := 0
			contributors := 0
			downloadCount := 0

			if pkg.InsightsV2 != nil {
				downloadCount = int(pkg.InsightsV2.DownloadCount)
				if pkg.InsightsV2.ModifiedAt != nil {
					lastUpdated = pkg.InsightsV2.ModifiedAt.AsTime().Format("2006-01-02")
				}

				if len(pkg.InsightsV2.ProjectInsights) > 0 {
					insight := pkg.InsightsV2.ProjectInsights[0]

					if insight != nil {
						if insight.Stars != nil {
							stars = int(*insight.Stars)
						}
						if insight.Contributors != nil {
							contributors = int(*insight.Contributors)
						}
					}
				}
			}

			popularity = append(popularity, templates.PopularityMetric{
				Package:      pkg.Name,
				Version:      pkg.Version,
				Downloads:    downloadCount,
				Stars:        stars,
				Contributors: contributors,
				LastUpdated:  lastUpdated,
			})
		}
	}

	return popularity
}
