package reporter

import (
	"fmt"
	"os"
	"strings"

	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	"github.com/charmbracelet/glamour"
	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/malysis"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
)

// SkillReporterConfig configures the skill reporter
type SkillReporterConfig struct {
	// Whether to show detailed evidence in output
	ShowEvidence bool
}

// DefaultSkillReporterConfig returns the default configuration
func DefaultSkillReporterConfig() SkillReporterConfig {
	return SkillReporterConfig{
		ShowEvidence: true,
	}
}

// skillReporter provides a CLI-focused reporter specifically for Agent Skills
type skillReporter struct {
	config        SkillReporterConfig
	manifest      *models.PackageManifest
	events        []*analyzer.AnalyzerEvent
	malwareReport *malysisv1.Report
	analysisID    string
	mdRenderer    *glamour.TermRenderer
}

var _ Reporter = (*skillReporter)(nil)

// NewSkillReporter creates a new skill reporter
func NewSkillReporter(config SkillReporterConfig) *skillReporter {
	// Create a glamour renderer with a compact style for evidence rendering
	renderer, _ := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(70),
	)

	return &skillReporter{
		config:     config,
		events:     make([]*analyzer.AnalyzerEvent, 0),
		mdRenderer: renderer,
	}
}

func (r *skillReporter) Name() string {
	return "Agent Skill Reporter"
}

func (r *skillReporter) AddManifest(manifest *models.PackageManifest) {
	r.manifest = manifest

	// Extract malware analysis result from the skill package
	packages := manifest.GetPackages()
	if len(packages) > 0 {
		pkg := packages[0]
		if ma := pkg.GetMalwareAnalysisResult(); ma != nil {
			r.malwareReport = ma.Report
			r.analysisID = ma.AnalysisId
		}
	}
}

func (r *skillReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	r.events = append(r.events, event)
}

func (r *skillReporter) AddPolicyEvent(_ *policy.PolicyEvent) {
	// Not used for skill scanning
}

func (r *skillReporter) Finish() error {
	return r.render()
}

// render generates the CLI output
func (r *skillReporter) render() error {
	if r.manifest == nil {
		return fmt.Errorf("no manifest to report")
	}

	packages := r.manifest.GetPackages()
	if len(packages) == 0 {
		return fmt.Errorf("no packages found in manifest")
	}

	pkg := packages[0]

	// Print scan summary (header + skill info + verdict)
	r.printScanSummary(pkg)

	// Print key findings if available and requested
	if r.config.ShowEvidence && (pkg.IsMalware() || pkg.IsSuspicious()) {
		r.printKeyFindings()
	}

	// Print recommendation
	r.printRecommendation(pkg)

	// Print footer with analysis URL
	r.printFooter()

	return nil
}

// printScanSummary prints header, skill info, and verdict emphasizing malicious code detection
func (r *skillReporter) printScanSummary(pkg *models.Package) {
	// Header - emphasize malicious code analysis
	fmt.Fprintf(os.Stderr, "\n%s\n", text.Bold.Sprint("Malicious Code Analysis"))
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("─", 24))

	// Skill info - compact one-liner
	fmt.Fprintf(os.Stderr, "%s @ %s\n\n", pkg.GetName(), pkg.GetVersion())

	// Verdict with symbol - focus on malicious code detection
	var verdictSymbol, verdictText string

	if r.malwareReport != nil && r.malwareReport.GetInference() != nil {
		inference := r.malwareReport.GetInference()
		confidence := strings.TrimPrefix(inference.GetConfidence().String(), "CONFIDENCE_")

		if pkg.IsMalware() {
			verdictSymbol = text.FgRed.Sprint("✗")
			verdictText = text.FgRed.Sprint(text.Bold.Sprint("MALICIOUS CODE DETECTED"))

			// Count behaviors
			behaviors := r.getTopFindings(20)
			fmt.Fprintf(os.Stderr, "%s %s %s\n\n", verdictSymbol, verdictText,
				text.Faint.Sprint(fmt.Sprintf("(%s Confidence)", confidence)))

			fmt.Fprintf(os.Stderr, "%s\n", text.Bold.Sprint("Analysis Summary:"))
			fmt.Fprintf(os.Stderr, "  - Identified %d malicious code patterns\n", len(behaviors))
			fmt.Fprintf(os.Stderr, "  - Skill contains intentionally harmful behaviors\n")
			fmt.Fprintf(os.Stderr, "  - Code analysis reveals security threats\n\n")
		} else if pkg.IsSuspicious() {
			verdictSymbol = text.FgYellow.Sprint("⚠")
			verdictText = text.FgYellow.Sprint(text.Bold.Sprint("SUSPICIOUS CODE DETECTED"))

			// Count behaviors
			behaviors := r.getTopFindings(20)
			fmt.Fprintf(os.Stderr, "%s %s %s\n\n", verdictSymbol, verdictText,
				text.Faint.Sprint(fmt.Sprintf("(%s Confidence)", confidence)))

			fmt.Fprintf(os.Stderr, "%s\n", text.Bold.Sprint("Analysis Summary:"))
			fmt.Fprintf(os.Stderr, "  - Found %d potentially harmful code patterns\n", len(behaviors))
			fmt.Fprintf(os.Stderr, "  - Code exhibits suspicious behaviors\n")
			fmt.Fprintf(os.Stderr, "  - Further review recommended\n\n")
		} else {
			verdictSymbol = text.FgGreen.Sprint("✓")
			verdictText = text.FgGreen.Sprint(text.Bold.Sprint("NO MALICIOUS CODE DETECTED"))

			fmt.Fprintf(os.Stderr, "%s %s\n\n", verdictSymbol, verdictText)

			// Get file count from analysis
			fileCount := len(r.malwareReport.GetFileEvidences())
			if fileCount == 0 {
				fileCount = len(r.malwareReport.GetProjectEvidences())
			}

			fmt.Fprintf(os.Stderr, "%s\n", text.Bold.Sprint("Analysis Summary:"))
			if fileCount > 0 {
				fmt.Fprintf(os.Stderr, "  - Analyzed %d files from repository\n", fileCount)
			}

			fmt.Fprintf(os.Stderr, "  - No malicious behaviors identified\n")
			fmt.Fprintf(os.Stderr, "  - All code patterns appear legitimate\n\n")
		}
	} else {
		// No malware report available (query mode with no data)
		verdictSymbol = text.FgYellow.Sprint("●")
		verdictText = text.FgYellow.Sprint(text.Bold.Sprint("NO ANALYSIS DATA AVAILABLE"))

		fmt.Fprintf(os.Stderr, "%s %s\n\n", verdictSymbol, verdictText)

		fmt.Fprintf(os.Stderr, "%s\n", text.Bold.Sprint("Analysis Summary:"))
		fmt.Fprintf(os.Stderr, "  - No malware analysis data available\n")
		fmt.Fprintf(os.Stderr, "  - Query mode has limited coverage\n")
		fmt.Fprintf(os.Stderr, "  - Active scanning required for full analysis\n\n")
	}
}

// printKeyFindings prints detailed malicious behaviors with evidence
func (r *skillReporter) printKeyFindings() {
	if r.malwareReport == nil {
		return
	}

	// Get top evidence items (5-7 behaviors)
	evidenceItems := r.getTopEvidenceItems(7)
	if len(evidenceItems) == 0 {
		return
	}

	// Choose header based on severity
	header := "Detected Behaviors:"
	if r.manifest != nil {
		packages := r.manifest.GetPackages()
		if len(packages) > 0 && packages[0].IsMalware() {
			header = "Malicious Behaviors Detected:"
		}
	}

	fmt.Fprintf(os.Stderr, "%s\n\n", text.Bold.Sprint(header))

	for i, item := range evidenceItems {
		// Print behavior title (numbered) - trim to prevent overflow
		trimmedBehavior := r.trimText(item.behavior, 80)
		fmt.Fprintf(os.Stderr, "%s. %s\n",
			text.Bold.Sprint(fmt.Sprintf("%d", i+1)),
			text.Bold.Sprint(trimmedBehavior))

		// Print description (markdown rendered) if available
		if item.title != "" {
			// Trim title to prevent overflow (max 140 chars = ~2 lines)
			trimmedTitle := r.trimText(item.title, 140)

			// Render with glamour (it handles wrapping automatically)
			if r.mdRenderer != nil {
				rendered, err := r.mdRenderer.Render(trimmedTitle)
				if err == nil {
					lines := strings.Split(strings.TrimSpace(rendered), "\n")
					// Limit to 2 lines
					maxLines := 2
					for idx, line := range lines {
						if idx >= maxLines {
							break
						}
						fmt.Fprintf(os.Stderr, "   %s\n", text.Faint.Sprint(line))
					}
				}
			}
		}

		// Print details (markdown rendered) if available
		if item.details != "" {
			// Trim details to prevent excessive output (max 350 chars = ~5 lines)
			trimmedDetails := r.trimText(item.details, 350)

			fmt.Fprintln(os.Stderr)
			// Render with glamour (it handles wrapping automatically)
			if r.mdRenderer != nil {
				rendered, err := r.mdRenderer.Render(trimmedDetails)
				if err == nil {
					lines := strings.Split(strings.TrimSpace(rendered), "\n")
					// Limit to 5 lines
					maxLines := 5
					for idx, line := range lines {
						if idx >= maxLines {
							break
						}
						fmt.Fprintf(os.Stderr, "   %s\n", text.Faint.Sprint(line))
					}
				}
			}
		}

		// Print metadata (location, confidence)
		fmt.Fprintln(os.Stderr)
		if item.location != "" {
			fmt.Fprintf(os.Stderr, "   %s %s\n",
				text.Faint.Sprint("Location:"),
				text.Faint.Sprint(item.location))
		}
		fmt.Fprintf(os.Stderr, "   %s %s\n",
			text.Faint.Sprint("Confidence:"),
			r.colorizeConfidence(item.confidence))

		fmt.Fprintln(os.Stderr)
	}
}

// printRecommendation prints recommendations for malicious code handling
func (r *skillReporter) printRecommendation(pkg *models.Package) {
	// Check if no analysis data is available
	if r.malwareReport == nil {
		fmt.Fprintf(os.Stderr, "%s\n", text.Bold.Sprint("Recommendations:"))
		fmt.Fprintf(os.Stderr, "%s\n",
			text.FgYellow.Sprint("→ Enable active scanning for comprehensive analysis"))
		fmt.Fprintf(os.Stderr, "%s\n\n",
			text.FgYellow.Sprint("→ Run 'vet cloud quickstart' to sign up for full malware analysis"))
		return
	}

	// Handle cases with analysis data
	if pkg.IsMalware() {
		fmt.Fprintf(os.Stderr, "%s\n", text.Bold.Sprint("Recommendations:"))
		fmt.Fprintf(os.Stderr, "%s\n",
			text.FgRed.Sprint("→ DO NOT USE - This skill contains malicious code"))
		fmt.Fprintf(os.Stderr, "%s\n\n",
			text.FgRed.Sprint("→ Report to skill maintainer and registry immediately"))
	} else if pkg.IsSuspicious() {
		fmt.Fprintf(os.Stderr, "%s\n", text.Bold.Sprint("Recommendations:"))
		fmt.Fprintf(os.Stderr, "%s\n",
			text.FgYellow.Sprint("→ Review all code behaviors before using"))
		fmt.Fprintf(os.Stderr, "%s\n\n",
			text.FgYellow.Sprint("→ Consider alternative skills with verified code"))
	}
	// No recommendation needed for SAFE skills
}

// printFooter prints the analysis URL
func (r *skillReporter) printFooter() {
	if r.analysisID != "" {
		reportURL := malysis.ReportURL(r.analysisID)
		fmt.Fprintf(os.Stderr, "%s\n\n",
			text.Faint.Sprint("→ View detailed analysis: "+reportURL))
	}
}

// colorizeConfidence returns a colorized confidence string
func (r *skillReporter) colorizeConfidence(confidence string) string {
	switch confidence {
	case "HIGH":
		return text.FgRed.Sprint(confidence)
	case "MEDIUM":
		return text.FgYellow.Sprint(confidence)
	case "LOW":
		return text.FgGreen.Sprint(confidence)
	default:
		return confidence
	}
}

// evidenceItem represents a malicious behavior with full details
type evidenceItem struct {
	behavior        string
	title           string
	details         string
	location        string
	confidence      string
	confidenceValue int // For sorting: HIGH=3, MEDIUM=2, LOW=1
}

// getTopEvidenceItems extracts the top N most critical evidence items with full details
func (r *skillReporter) getTopEvidenceItems(maxItems int) []evidenceItem {
	if r.malwareReport == nil {
		return []evidenceItem{}
	}

	items := []evidenceItem{}

	// Extract file evidence
	for _, fileEvidence := range r.malwareReport.GetFileEvidences() {
		evidence := fileEvidence.GetEvidence()
		if evidence == nil {
			continue
		}

		behavior := evidence.GetBehavior()
		if behavior == "" {
			continue
		}

		// Map confidence to numeric value for sorting
		confidenceStr := strings.TrimPrefix(evidence.GetConfidence().String(), "CONFIDENCE_")
		confidenceValue := 0
		switch confidenceStr {
		case "HIGH":
			confidenceValue = 3
		case "MEDIUM":
			confidenceValue = 2
		case "LOW":
			confidenceValue = 1
		}

		// Build location string
		location := fileEvidence.GetFileKey()
		if fileEvidence.GetLine() > 0 {
			location = fmt.Sprintf("%s:%d", location, fileEvidence.GetLine())
		}

		items = append(items, evidenceItem{
			behavior:        behavior,
			title:           evidence.GetTitle(),
			details:         evidence.GetDetails(),
			location:        location,
			confidence:      confidenceStr,
			confidenceValue: confidenceValue,
		})
	}

	// Extract project evidence
	for _, projEvidence := range r.malwareReport.GetProjectEvidences() {
		evidence := projEvidence.GetEvidence()
		if evidence == nil {
			continue
		}

		behavior := evidence.GetBehavior()
		if behavior == "" {
			continue
		}

		confidenceStr := strings.TrimPrefix(evidence.GetConfidence().String(), "CONFIDENCE_")
		confidenceValue := 0
		switch confidenceStr {
		case "HIGH":
			confidenceValue = 3
		case "MEDIUM":
			confidenceValue = 2
		case "LOW":
			confidenceValue = 1
		}

		// Build location string from project
		location := "Project-level"
		if proj := projEvidence.GetProject(); proj != nil && proj.GetUrl() != "" {
			location = proj.GetUrl()
		}

		items = append(items, evidenceItem{
			behavior:        behavior,
			title:           evidence.GetTitle(),
			details:         evidence.GetDetails(),
			location:        location,
			confidence:      confidenceStr,
			confidenceValue: confidenceValue,
		})
	}

	// Sort by confidence (highest first)
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].confidenceValue > items[i].confidenceValue {
				items[i], items[j] = items[j], items[i]
			}
		}
	}

	// Deduplicate by behavior and take top N
	seen := make(map[string]bool)
	result := []evidenceItem{}
	for _, item := range items {
		if !seen[item.behavior] {
			seen[item.behavior] = true
			result = append(result, item)
			if len(result) >= maxItems {
				break
			}
		}
	}

	return result
}

// getTopFindings extracts just the behavior strings (used for counting)
func (r *skillReporter) getTopFindings(maxFindings int) []string {
	items := r.getTopEvidenceItems(maxFindings)
	result := []string{}
	for _, item := range items {
		result = append(result, item.behavior)
	}
	return result
}

// trimText trims text to specified length and adds ellipsis if needed
func (r *skillReporter) trimText(text string, maxLen int) string {
	if len(text) <= maxLen {
		return text
	}
	if maxLen < 3 {
		return "..."
	}
	return text[:maxLen-3] + "..."
}

// wrapText wraps text to the specified width
func (r *skillReporter) wrapText(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{}
	}

	var lines []string
	var currentLine strings.Builder

	for _, word := range words {
		if currentLine.Len() == 0 {
			currentLine.WriteString(word)
		} else if currentLine.Len()+1+len(word) <= width {
			currentLine.WriteString(" ")
			currentLine.WriteString(word)
		} else {
			lines = append(lines, currentLine.String())
			currentLine.Reset()
			currentLine.WriteString(word)
		}
	}

	if currentLine.Len() > 0 {
		lines = append(lines, currentLine.String())
	}

	return lines
}
