package reporter

import (
	"fmt"
	"os"
	"strings"

	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	"github.com/jedib0t/go-pretty/v6/table"
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
	analysisId    string
}

var _ Reporter = (*skillReporter)(nil)

// NewSkillReporter creates a new skill reporter
func NewSkillReporter(config SkillReporterConfig) *skillReporter {
	return &skillReporter{
		config: config,
		events: make([]*analyzer.AnalyzerEvent, 0),
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
			r.analysisId = ma.AnalysisId
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

	// Print header
	r.printHeader()

	// Print skill information
	r.printSkillInfo(pkg)

	// Print scan verdict
	r.printVerdict(pkg)

	// Print analysis details if available
	if r.malwareReport != nil {
		r.printAnalysisDetails()

		// Print evidence if requested and available
		if r.config.ShowEvidence && (pkg.IsMalware() || pkg.IsSuspicious()) {
			r.printEvidence()
		}
	}

	// Print recommendations
	r.printRecommendations(pkg)

	// Print footer with link to detailed analysis
	r.printFooter()

	return nil
}

func (r *skillReporter) printHeader() {
	fmt.Fprintf(os.Stderr, "\n%s\n", text.Bold.Sprint("═══════════════════════════════════════════════════════════════"))
	fmt.Fprintf(os.Stderr, "%s\n", text.Bold.Sprint("  Agent Skill Security Scan Report"))
	fmt.Fprintf(os.Stderr, "%s\n\n", text.Bold.Sprint("═══════════════════════════════════════════════════════════════"))
}

func (r *skillReporter) printSkillInfo(pkg *models.Package) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stderr)
	t.SetStyle(table.StyleLight)
	t.Style().Options.SeparateRows = false

	t.AppendRow(table.Row{"Skill", pkg.GetName()})
	t.AppendRow(table.Row{"Version", pkg.GetVersion()})
	t.AppendRow(table.Row{"Ecosystem", pkg.Manifest.Ecosystem})
	t.AppendRow(table.Row{"Source", r.manifest.GetDisplayPath()})

	if r.analysisId != "" {
		t.AppendRow(table.Row{"Analysis ID", r.analysisId})
	}

	t.Render()
	fmt.Fprintln(os.Stderr)
}

func (r *skillReporter) printVerdict(pkg *models.Package) {
	var verdictIcon, verdictText, verdictColor string

	if pkg.IsMalware() {
		verdictIcon = "❌"
		verdictText = "MALICIOUS"
		verdictColor = text.FgRed.Sprint(verdictText)
	} else if pkg.IsSuspicious() {
		verdictIcon = "⚠️ "
		verdictText = "SUSPICIOUS"
		verdictColor = text.FgYellow.Sprint(verdictText)
	} else {
		verdictIcon = "✅"
		verdictText = "SAFE"
		verdictColor = text.FgGreen.Sprint(verdictText)
	}

	fmt.Fprintf(os.Stderr, "%s %s %s\n\n",
		text.Bold.Sprint("Security Verdict:"),
		verdictIcon,
		text.Bold.Sprint(verdictColor))
}

func (r *skillReporter) printAnalysisDetails() {
	if r.malwareReport == nil {
		return
	}

	inference := r.malwareReport.GetInference()
	if inference == nil {
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stderr)
	t.SetStyle(table.StyleLight)
	t.SetTitle("Analysis Details")
	t.Style().Options.SeparateRows = false

	// Show malware classification
	isMalware := "No"
	if inference.GetIsMalware() {
		isMalware = text.FgRed.Sprint("Yes")
	}
	t.AppendRow(table.Row{"Malware Detected", isMalware})

	// Show confidence level
	confidence := inference.GetConfidence().String()
	confidence = strings.TrimPrefix(confidence, "CONFIDENCE_")
	confidenceDisplay := r.colorizeConfidence(confidence)
	t.AppendRow(table.Row{"Confidence", confidenceDisplay})

	// Show summary if available
	if summary := inference.GetSummary(); summary != "" {
		t.AppendRow(table.Row{"Summary", summary})
	}

	t.Render()
	fmt.Fprintln(os.Stderr)
}

func (r *skillReporter) printEvidence() {
	if r.malwareReport == nil {
		return
	}

	fileEvidences := r.malwareReport.GetFileEvidences()
	projectEvidences := r.malwareReport.GetProjectEvidences()

	if len(fileEvidences) == 0 && len(projectEvidences) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "%s\n", text.Bold.Sprint("Security Evidence:"))
	fmt.Fprintln(os.Stderr)

	evidenceNum := 1

	// Print file-level evidence
	for _, fileEvidence := range fileEvidences {
		evidence := fileEvidence.GetEvidence()
		if evidence == nil {
			continue
		}

		// Get behavior and wrap if too long
		behavior := evidence.GetBehavior()
		if behavior == "" {
			behavior = "Security Finding"
		}

		// Print evidence header with wrapped behavior if needed
		fmt.Fprintf(os.Stderr, "  %d. ", evidenceNum)
		if len(behavior) > 80 {
			// Wrap long behavior text
			wrappedBehavior := r.wrapText(behavior, 70)
			for i, line := range wrappedBehavior {
				if i == 0 {
					fmt.Fprintf(os.Stderr, "%s\n", text.Bold.Sprint(line))
				} else {
					fmt.Fprintf(os.Stderr, "     %s\n", text.Bold.Sprint(line))
				}
			}
			fmt.Fprintf(os.Stderr, "     (File: %s, Line: %d)\n",
				text.Faint.Sprint(fileEvidence.GetFileKey()),
				fileEvidence.GetLine())
		} else {
			fmt.Fprintf(os.Stderr, "%s (File: %s, Line: %d)\n",
				text.Bold.Sprint(behavior),
				text.Faint.Sprint(fileEvidence.GetFileKey()),
				fileEvidence.GetLine())
		}

		if title := evidence.GetTitle(); title != "" {
			fmt.Fprintf(os.Stderr, "     %s\n", title)
		}

		if details := evidence.GetDetails(); details != "" {
			// Wrap long descriptions
			wrapped := r.wrapText(details, 70)
			for _, line := range wrapped {
				fmt.Fprintf(os.Stderr, "     %s\n", text.Faint.Sprint(line))
			}
		}

		// Show confidence for this evidence
		conf := evidence.GetConfidence().String()
		conf = strings.TrimPrefix(conf, "CONFIDENCE_")
		fmt.Fprintf(os.Stderr, "     Confidence: %s\n", r.colorizeConfidence(conf))

		// Show MITRE ATT&CK info if available
		if mitreId := evidence.GetMitreAttackId(); mitreId != "" {
			fmt.Fprintf(os.Stderr, "     MITRE ATT&CK: %s", mitreId)
			if mitreClass := evidence.GetMitreAttackClassification(); mitreClass != "" {
				fmt.Fprintf(os.Stderr, " (%s)", mitreClass)
			}
			fmt.Fprintln(os.Stderr)
		}

		fmt.Fprintln(os.Stderr)
		evidenceNum++
	}

	// Print project-level evidence
	for _, projEvidence := range projectEvidences {
		evidence := projEvidence.GetEvidence()
		if evidence == nil {
			continue
		}

		// Get behavior and wrap if too long
		behavior := evidence.GetBehavior()
		if behavior == "" {
			behavior = "Security Finding"
		}

		projectInfo := ""
		if proj := projEvidence.GetProject(); proj != nil {
			projectInfo = fmt.Sprintf(" (Project: %s)", proj.GetUrl())
		}

		// Print evidence header with wrapped behavior if needed
		fmt.Fprintf(os.Stderr, "  %d. ", evidenceNum)
		if len(behavior) > 80 {
			// Wrap long behavior text
			wrappedBehavior := r.wrapText(behavior, 70)
			for i, line := range wrappedBehavior {
				if i == 0 {
					fmt.Fprintf(os.Stderr, "%s\n", text.Bold.Sprint(line))
				} else {
					fmt.Fprintf(os.Stderr, "     %s\n", text.Bold.Sprint(line))
				}
			}
			if projectInfo != "" {
				fmt.Fprintf(os.Stderr, "     %s\n", text.Faint.Sprint(projectInfo))
			}
		} else {
			fmt.Fprintf(os.Stderr, "%s%s\n",
				text.Bold.Sprint(behavior),
				text.Faint.Sprint(projectInfo))
		}

		if title := evidence.GetTitle(); title != "" {
			fmt.Fprintf(os.Stderr, "     %s\n", title)
		}

		if details := evidence.GetDetails(); details != "" {
			// Wrap long descriptions
			wrapped := r.wrapText(details, 70)
			for _, line := range wrapped {
				fmt.Fprintf(os.Stderr, "     %s\n", text.Faint.Sprint(line))
			}
		}

		// Show confidence for this evidence
		conf := evidence.GetConfidence().String()
		conf = strings.TrimPrefix(conf, "CONFIDENCE_")
		fmt.Fprintf(os.Stderr, "     Confidence: %s\n", r.colorizeConfidence(conf))

		// Show MITRE ATT&CK info if available
		if mitreId := evidence.GetMitreAttackId(); mitreId != "" {
			fmt.Fprintf(os.Stderr, "     MITRE ATT&CK: %s", mitreId)
			if mitreClass := evidence.GetMitreAttackClassification(); mitreClass != "" {
				fmt.Fprintf(os.Stderr, " (%s)", mitreClass)
			}
			fmt.Fprintln(os.Stderr)
		}

		fmt.Fprintln(os.Stderr)
		evidenceNum++
	}
}

func (r *skillReporter) printRecommendations(pkg *models.Package) {
	fmt.Fprintf(os.Stderr, "%s\n", text.Bold.Sprint("Recommendations:"))
	fmt.Fprintln(os.Stderr)

	if pkg.IsMalware() {
		fmt.Fprintf(os.Stderr, "  %s Do not use this skill in your application\n",
			text.FgRed.Sprint("❌"))
		fmt.Fprintf(os.Stderr, "  %s Review the security evidence above carefully\n",
			text.FgRed.Sprint("🔍"))
		fmt.Fprintf(os.Stderr, "  %s Consider reporting this to the skill maintainer or registry\n",
			text.FgRed.Sprint("📢"))
	} else if pkg.IsSuspicious() {
		fmt.Fprintf(os.Stderr, "  %s Exercise caution when using this skill\n",
			text.FgYellow.Sprint("⚠️ "))
		fmt.Fprintf(os.Stderr, "  %s Review the repository code and maintainer reputation\n",
			text.FgYellow.Sprint("🔍"))
		fmt.Fprintf(os.Stderr, "  %s Consider using a verified alternative if available\n",
			text.FgYellow.Sprint("💡"))
		fmt.Fprintf(os.Stderr, "  %s Run active malware scanning with authentication for definitive results\n",
			text.FgYellow.Sprint("🔐"))
	} else {
		fmt.Fprintf(os.Stderr, "  %s Skill appears safe to use based on malware analysis\n",
			text.FgGreen.Sprint("✅"))
		fmt.Fprintf(os.Stderr, "  %s Always review skill code before adding to your project\n",
			text.FgGreen.Sprint("📖"))
		fmt.Fprintf(os.Stderr, "  %s Keep the skill updated to latest secure version\n",
			text.FgGreen.Sprint("🔄"))
	}

	fmt.Fprintln(os.Stderr)
}

func (r *skillReporter) printFooter() {
	if r.analysisId != "" {
		reportURL := malysis.ReportURL(r.analysisId)
		fmt.Fprintf(os.Stderr, "%s\n",
			text.Faint.Sprint("For detailed analysis, visit: "+reportURL))
	}

	fmt.Fprintf(os.Stderr, "%s\n",
		text.Faint.Sprint("Powered by SafeDep Malysis - https://safedep.io"))
	fmt.Fprintln(os.Stderr)
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
