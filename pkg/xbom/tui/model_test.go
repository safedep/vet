package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestModel() *model {
	sink := &EventSink{}
	return newModel(Config{}, sink)
}

func TestModelFileScannedMsg(t *testing.T) {
	m := newTestModel()

	updated, _ := m.Update(fileScannedMsg{filePath: "src/main.py"})
	model := updated.(*model)

	assert.Equal(t, 1, model.stats.filesScanned)
	assert.Equal(t, "src/main.py", model.stats.latestFile)
}

func TestModelFileScannedMsgMultiple(t *testing.T) {
	m := newTestModel()

	m.Update(fileScannedMsg{filePath: "a.py"})
	updated, _ := m.Update(fileScannedMsg{filePath: "b.py"})
	model := updated.(*model)

	assert.Equal(t, 2, model.stats.filesScanned)
	assert.Equal(t, "b.py", model.stats.latestFile)
}

func TestModelMatchFoundMsg(t *testing.T) {
	m := newTestModel()

	updated, _ := m.Update(matchFoundMsg{
		signatureID: "openai.client",
		tags:        []string{"ai", "llm"},
		language:    "python",
		filePath:    "src/api.py",
	})
	model := updated.(*model)

	assert.Equal(t, 1, model.stats.totalMatches)
	assert.True(t, model.stats.filesAffected["src/api.py"])
	assert.Equal(t, 1, model.stats.signatureCounts["openai.client"])
	assert.Equal(t, []string{"ai", "llm"}, model.stats.signatureTags["openai.client"])
	assert.Equal(t, 1, model.stats.languageCounts["python"])
}

func TestModelMatchFoundMsgAccumulates(t *testing.T) {
	m := newTestModel()

	m.Update(matchFoundMsg{
		signatureID: "openai.client",
		tags:        []string{"ai"},
		language:    "python",
		filePath:    "a.py",
	})
	m.Update(matchFoundMsg{
		signatureID: "openai.client",
		tags:        []string{"ai"},
		language:    "python",
		filePath:    "b.py",
	})
	updated, _ := m.Update(matchFoundMsg{
		signatureID: "aws.s3",
		tags:        []string{"cloud"},
		language:    "python",
		filePath:    "a.py",
	})
	model := updated.(*model)

	assert.Equal(t, 3, model.stats.totalMatches)
	assert.Len(t, model.stats.filesAffected, 2) // a.py and b.py
	assert.Equal(t, 2, model.stats.signatureCounts["openai.client"])
	assert.Equal(t, 1, model.stats.signatureCounts["aws.s3"])
	assert.Equal(t, 1, len(model.stats.languageCounts))
	assert.Equal(t, 3, model.stats.languageCounts["python"])
}

func TestModelScanDoneMsg(t *testing.T) {
	m := newTestModel()

	updated, cmd := m.Update(scanDoneMsg{err: nil})
	model := updated.(*model)

	assert.Equal(t, phaseSummary, model.phase)
	assert.True(t, model.done)
	assert.Nil(t, model.err)
	assert.NotNil(t, cmd) // should be tea.Quit
}

func TestModelScanDoneMsgWithError(t *testing.T) {
	m := newTestModel()

	updated, cmd := m.Update(scanDoneMsg{err: errors.New("permission denied")})
	model := updated.(*model)

	assert.Equal(t, phaseSummary, model.phase)
	assert.True(t, model.done)
	require.Error(t, model.err)
	assert.Equal(t, "permission denied", model.err.Error())
	assert.NotNil(t, cmd)
}

func TestModelCtrlCQuits(t *testing.T) {
	m := newTestModel()

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	model := updated.(*model)

	assert.True(t, model.done)
	assert.NotNil(t, cmd) // should be tea.Quit
}

func TestModelWindowSize(t *testing.T) {
	m := newTestModel()

	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	model := updated.(*model)

	assert.Equal(t, 120, model.width)
}

func TestViewScanningPhase(t *testing.T) {
	m := newTestModel()

	m.Update(fileScannedMsg{filePath: "src/api/openai_client.py"})
	m.Update(fileScannedMsg{filePath: "src/main.py"})
	m.Update(matchFoundMsg{
		signatureID: "openai.client",
		tags:        []string{"ai"},
		language:    "python",
		filePath:    "src/api/openai_client.py",
	})

	view := m.View()

	assert.Contains(t, view, "Scanning code...")
	assert.Contains(t, view, "Files scanned:")
	assert.Contains(t, view, "2")
	assert.Contains(t, view, "Matches:")
	assert.Contains(t, view, "1")
	assert.Contains(t, view, "Latest:")
	assert.Contains(t, view, "src/main.py")
}

func TestViewSummaryPhase(t *testing.T) {
	m := newTestModel()

	// Simulate some matches
	m.Update(matchFoundMsg{signatureID: "openai.client", tags: []string{"ai", "llm"}, language: "python", filePath: "a.py"})
	m.Update(matchFoundMsg{signatureID: "openai.client", tags: []string{"ai", "llm"}, language: "python", filePath: "b.py"})
	m.Update(matchFoundMsg{signatureID: "aws.s3", tags: []string{"cloud"}, language: "python", filePath: "a.py"})

	// Transition to summary
	m.Update(scanDoneMsg{err: nil})

	view := m.View()

	assert.Contains(t, view, "Code Scan Summary")
	assert.Contains(t, view, "Findings:")
	assert.Contains(t, view, "3")
	assert.Contains(t, view, "Files:")
	assert.Contains(t, view, "2")
	assert.Contains(t, view, "Top Signatures")
	assert.Contains(t, view, "openai.client")
	assert.Contains(t, view, "aws.s3")
	assert.Contains(t, view, "█")
	assert.Contains(t, view, "[ai]")
	assert.Contains(t, view, "[cloud]")
}

func TestViewSummaryNoMatches(t *testing.T) {
	m := newTestModel()

	m.Update(scanDoneMsg{err: nil})

	view := m.View()

	assert.Contains(t, view, "Code Scan Summary")
	assert.Contains(t, view, "0") // findings count
	assert.NotContains(t, view, "Top Signatures")
}

func TestViewSummaryWithError(t *testing.T) {
	m := newTestModel()

	m.Update(scanDoneMsg{err: errors.New("scan failed")})

	view := m.View()

	assert.Contains(t, view, "✗")
	assert.Contains(t, view, "scan failed")
	assert.NotContains(t, view, "Code Scan Summary")
}

func TestEventSinkNilProgram(t *testing.T) {
	sink := &EventSink{}
	assert.NotPanics(t, func() {
		sink.FileScanned("test.py")
		sink.ScanDone(nil)
	})
}

func TestBuildSignaturesContentOrdering(t *testing.T) {
	m := newTestModel()

	// Add signatures with different counts
	for i := 0; i < 15; i++ {
		m.Update(matchFoundMsg{signatureID: "openai.client", tags: []string{"ai"}, language: "python", filePath: "a.py"})
	}
	for i := 0; i < 8; i++ {
		m.Update(matchFoundMsg{signatureID: "aws.s3", tags: []string{"cloud"}, language: "python", filePath: "b.py"})
	}
	for i := 0; i < 2; i++ {
		m.Update(matchFoundMsg{signatureID: "jwt.sign", tags: []string{"crypto"}, language: "javascript", filePath: "c.js"})
	}

	m.phase = phaseSummary
	content := m.buildSignaturesContent()

	// openai.client should appear before aws.s3, which should appear before jwt.sign
	openaiIdx := strings.Index(content, "openai.client")
	awsIdx := strings.Index(content, "aws.s3")
	jwtIdx := strings.Index(content, "jwt.sign")

	assert.Greater(t, awsIdx, openaiIdx, "openai.client should appear before aws.s3")
	assert.Greater(t, jwtIdx, awsIdx, "aws.s3 should appear before jwt.sign")
}

func TestBuildSignaturesContentTopFiveLimit(t *testing.T) {
	m := newTestModel()

	// Add 7 different signatures
	sigs := []string{"sig1", "sig2", "sig3", "sig4", "sig5", "sig6", "sig7"}
	for i, sig := range sigs {
		for j := 0; j < len(sigs)-i; j++ {
			m.Update(matchFoundMsg{signatureID: sig, language: "go", filePath: "x.go"})
		}
	}

	m.phase = phaseSummary
	content := m.buildSignaturesContent()

	// Top 5 should be present
	for _, sig := range sigs[:5] {
		assert.Contains(t, content, sig)
	}
	// 6th and 7th should not
	assert.NotContains(t, content, "sig6")
	assert.NotContains(t, content, "sig7")
}
