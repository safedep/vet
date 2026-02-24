package tui

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

// Config controls the appearance and behavior of the xBOM TUI.
type Config struct {
	// Profile overrides the default color scheme. Nil uses DefaultProfile.
	Profile *ColorProfile
}

type phase int

const (
	phaseScanning phase = iota
	phaseSummary
)

const maxBarLen = 12

type scanStats struct {
	filesScanned    int
	totalMatches    int
	latestFile      string
	filesAffected   map[string]bool
	signatureCounts map[string]int
	signatureTags   map[string][]string
	languageCounts  map[string]int
}

type model struct {
	config    Config
	styles    Styles
	sink      *EventSink
	stats     scanStats
	phase     phase
	err       error
	done      bool
	spinner   spinner.Model
	width     int
	startTime time.Time
}

// ScanFunc is the function that performs the actual scan.
// It receives an EventSink to report progress.
type ScanFunc func(sink *EventSink) error

// Run starts the TUI, executes the scan function, and displays progress
// until completion. It blocks until the TUI exits.
func Run(scanFn ScanFunc, config Config) error {
	sink := &EventSink{}
	m := newModel(config, sink)

	p := tea.NewProgram(m, tea.WithoutSignalHandler())
	sink.program.Store(p)

	// Launch the scan in a goroutine
	go func() {
		err := scanFn(sink)
		sink.ScanDone(err)
	}()

	_, err := p.Run()
	if err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	if m.err != nil {
		return m.err
	}

	return nil
}

func newModel(config Config, sink *EventSink) *model {
	profile := DefaultProfile
	if config.Profile != nil {
		profile = *config.Profile
	}

	styles := NewStyles(profile)

	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = styles.Spinner

	width := 80
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		width = w
	}

	return &model{
		config: config,
		styles: styles,
		sink:   sink,
		stats: scanStats{
			filesAffected:   make(map[string]bool),
			signatureCounts: make(map[string]int),
			signatureTags:   make(map[string][]string),
			languageCounts:  make(map[string]int),
		},
		phase:     phaseScanning,
		spinner:   s,
		width:     width,
		startTime: time.Now(),
	}
}

func (m *model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.done = true
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width

	case spinner.TickMsg:
		if !m.done {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}

	case fileScannedMsg:
		m.stats.filesScanned++
		m.stats.latestFile = msg.filePath

	case matchFoundMsg:
		m.stats.totalMatches++
		m.stats.filesAffected[msg.filePath] = true
		m.stats.signatureCounts[msg.signatureID]++
		if _, ok := m.stats.signatureTags[msg.signatureID]; !ok {
			m.stats.signatureTags[msg.signatureID] = msg.tags
		}
		if msg.language != "" {
			m.stats.languageCounts[msg.language]++
		}

	case scanDoneMsg:
		m.phase = phaseSummary
		m.err = msg.err
		m.done = true
		return m, tea.Quit
	}

	return m, nil
}

func (m *model) View() string {
	var b strings.Builder

	if m.phase == phaseScanning {
		b.WriteString(m.viewScanning())
	} else {
		b.WriteString(m.viewSummary())
	}

	return b.String()
}

func (m *model) viewScanning() string {
	var b strings.Builder

	elapsed := time.Since(m.startTime).Truncate(time.Second)

	b.WriteString(fmt.Sprintf("\n  %s %s  %s\n",
		m.spinner.View(),
		m.styles.Title.Render("Scanning code..."),
		m.styles.Dim.Render(fmt.Sprintf("(%s)", elapsed)),
	))

	b.WriteString(fmt.Sprintf("\n  %s %s    %s %s\n",
		m.styles.StatLabel.Render("Files scanned:"),
		m.styles.Counter.Render(fmt.Sprintf("%d", m.stats.filesScanned)),
		m.styles.StatLabel.Render("Matches:"),
		m.styles.Counter.Render(fmt.Sprintf("%d", m.stats.totalMatches)),
	))

	if m.stats.latestFile != "" {
		file := m.stats.latestFile
		maxLen := m.width - 12
		if maxLen < 20 {
			maxLen = 20
		}
		if len(file) > maxLen {
			file = "..." + file[len(file)-maxLen+3:]
		}
		b.WriteString(fmt.Sprintf("\n  %s %s\n",
			m.styles.StatLabel.Render("Latest:"),
			m.styles.FileName.Render(file),
		))
	}

	return b.String()
}

func (m *model) viewSummary() string {
	var b strings.Builder

	if m.err != nil {
		b.WriteString(fmt.Sprintf("\n  %s %s\n",
			m.styles.ErrorText.Render("✗"),
			m.styles.ErrorText.Render("Scan failed: "+m.err.Error()),
		))
		return b.String()
	}

	// Summary box
	summaryContent := m.buildSummaryContent()
	boxWidth := m.width - 4
	if boxWidth < 40 {
		boxWidth = 40
	}
	b.WriteString("\n")
	b.WriteString(m.styles.SummaryBox.Width(boxWidth).Render(summaryContent))
	b.WriteString("\n")

	// Top signatures box (only if there are matches)
	if m.stats.totalMatches > 0 {
		sigContent := m.buildSignaturesContent()
		b.WriteString(m.styles.SignatureBox.Width(boxWidth).Render(sigContent))
		b.WriteString("\n")
	}

	return b.String()
}

func (m *model) buildSummaryContent() string {
	var b strings.Builder

	title := m.styles.Title.Render("Code Scan Summary")
	b.WriteString(fmt.Sprintf("  %s\n\n", title))

	findings := m.styles.StatValue.Render(fmt.Sprintf("%d", m.stats.totalMatches))
	files := m.styles.StatValue.Render(fmt.Sprintf("%d", len(m.stats.filesAffected)))
	langs := m.styles.StatValue.Render(fmt.Sprintf("%d", len(m.stats.languageCounts)))
	sigs := m.styles.StatValue.Render(fmt.Sprintf("%d", len(m.stats.signatureCounts)))

	b.WriteString(fmt.Sprintf("  %s %s    %s %s    %s %s\n",
		m.styles.StatLabel.Render("Findings:"), findings,
		m.styles.StatLabel.Render("Files:"), files,
		m.styles.StatLabel.Render("Languages:"), langs,
	))
	b.WriteString(fmt.Sprintf("  %s %s",
		m.styles.StatLabel.Render("Unique Signatures:"), sigs,
	))

	return b.String()
}

type sigEntry struct {
	name  string
	count int
	tags  []string
}

func (m *model) buildSignaturesContent() string {
	var b strings.Builder

	title := m.styles.Title.Render("Top Signatures")
	b.WriteString(fmt.Sprintf("  %s\n\n", title))

	// Sort signatures by count descending
	entries := make([]sigEntry, 0, len(m.stats.signatureCounts))
	for name, count := range m.stats.signatureCounts {
		entries = append(entries, sigEntry{
			name:  name,
			count: count,
			tags:  m.stats.signatureTags[name],
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count > entries[j].count
	})

	// Show top 5
	limit := 5
	if len(entries) < limit {
		limit = len(entries)
	}

	maxCount := 0
	if limit > 0 {
		maxCount = entries[0].count
	}

	// Find max name length for alignment
	maxNameLen := 0
	for i := 0; i < limit; i++ {
		if len(entries[i].name) > maxNameLen {
			maxNameLen = len(entries[i].name)
		}
	}

	for i := 0; i < limit; i++ {
		e := entries[i]

		// Pad name for alignment
		name := m.styles.SigName.Render(fmt.Sprintf("%-*s", maxNameLen, e.name))

		// Bar chart
		barLen := maxBarLen
		if maxCount > 0 {
			barLen = (e.count * maxBarLen) / maxCount
			if barLen < 1 {
				barLen = 1
			}
		}
		bar := m.styles.BarFull.Render(strings.Repeat("█", barLen))
		barPad := strings.Repeat(" ", maxBarLen-barLen)

		// Count
		count := m.styles.SigCount.Render(fmt.Sprintf("%-3d", e.count))

		// Tags
		tagStr := ""
		if len(e.tags) > 0 {
			tagParts := make([]string, len(e.tags))
			for j, tag := range e.tags {
				tagParts[j] = "[" + tag + "]"
			}
			tagStr = m.styles.TagBadge.Render(strings.Join(tagParts, ""))
		}

		b.WriteString(fmt.Sprintf("  %s  %s%s  %s  %s\n", name, bar, barPad, count, tagStr))
	}

	return b.String()
}
