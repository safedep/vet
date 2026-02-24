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

func TestViewSummaryNoMatches(t *testing.T) {
	m := newTestModel()

	m.Update(scanDoneMsg{err: nil})

	view := m.View()

	assert.Contains(t, view, "Code Scan Summary")
	assert.Contains(t, view, "0") // findings count
	assert.NotContains(t, view, "AI BOM")
	assert.NotContains(t, view, "CryptoBOM")
	assert.NotContains(t, view, "Cloud BOM")
	assert.NotContains(t, view, "Language Capabilities")
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

// --- Category classification tests ---

func TestClassifySignatureAI(t *testing.T) {
	assert.Equal(t, categoryAI, classifySignature([]string{"ai", "llm"}))
	assert.Equal(t, categoryAI, classifySignature([]string{"ml"}))
	assert.Equal(t, categoryAI, classifySignature([]string{"capability", "ai"}))
}

func TestClassifySignatureCrypto(t *testing.T) {
	assert.Equal(t, categoryCrypto, classifySignature([]string{"cryptography", "encryption"}))
	assert.Equal(t, categoryCrypto, classifySignature([]string{"hash"}))
	assert.Equal(t, categoryCrypto, classifySignature([]string{"crypto"}))
}

func TestClassifySignatureCloud(t *testing.T) {
	assert.Equal(t, categoryCloud, classifySignature([]string{"iaas"}))
	assert.Equal(t, categoryCloud, classifySignature([]string{"paas"}))
	assert.Equal(t, categoryCloud, classifySignature([]string{"saas"}))
	assert.Equal(t, categoryCloud, classifySignature([]string{"cloud"}))
}

func TestClassifySignatureCapability(t *testing.T) {
	assert.Equal(t, categoryCapability, classifySignature([]string{"capability"}))
	assert.Equal(t, categoryCapability, classifySignature([]string{"network", "http"}))
	assert.Equal(t, categoryCapability, classifySignature([]string{}))
}

func TestClassifySignatureAIPrecedence(t *testing.T) {
	// AI takes precedence over crypto and cloud tags
	assert.Equal(t, categoryAI, classifySignature([]string{"cryptography", "ai"}))
	assert.Equal(t, categoryAI, classifySignature([]string{"cloud", "ml"}))
}

func TestClassifySignatureCryptoPrecedence(t *testing.T) {
	// Crypto takes precedence over cloud
	assert.Equal(t, categoryCrypto, classifySignature([]string{"cloud", "encryption"}))
}

// --- Per-category box rendering tests ---

func TestViewSummaryAIBOMBox(t *testing.T) {
	m := newTestModel()

	m.Update(matchFoundMsg{signatureID: "openai.client", tags: []string{"ai", "llm"}, language: "python", filePath: "a.py"})
	m.Update(matchFoundMsg{signatureID: "anthropic.client", tags: []string{"ai", "llm"}, language: "python", filePath: "b.py"})
	m.Update(scanDoneMsg{err: nil})

	view := m.View()

	assert.Contains(t, view, "AI BOM")
	assert.Contains(t, view, "openai.client")
	assert.Contains(t, view, "anthropic.client")
	assert.NotContains(t, view, "CryptoBOM")
	assert.NotContains(t, view, "Cloud BOM")
	assert.NotContains(t, view, "Language Capabilities")
}

func TestViewSummaryCryptoBOMBox(t *testing.T) {
	m := newTestModel()

	m.Update(matchFoundMsg{signatureID: "crypto.aes", tags: []string{"cryptography", "encryption"}, language: "go", filePath: "a.go"})
	m.Update(matchFoundMsg{signatureID: "crypto.rsa", tags: []string{"cryptography", "signing"}, language: "go", filePath: "b.go"})
	m.Update(scanDoneMsg{err: nil})

	view := m.View()

	assert.Contains(t, view, "CryptoBOM")
	assert.Contains(t, view, "crypto.aes")
	assert.Contains(t, view, "crypto.rsa")
	assert.NotContains(t, view, "AI BOM")
}

func TestViewSummaryCloudBOMBox(t *testing.T) {
	m := newTestModel()

	m.Update(matchFoundMsg{signatureID: "gcp.storage", tags: []string{"iaas", "storage"}, language: "python", filePath: "a.py"})
	m.Update(scanDoneMsg{err: nil})

	view := m.View()

	assert.Contains(t, view, "Cloud BOM")
	assert.Contains(t, view, "gcp.storage")
	assert.NotContains(t, view, "AI BOM")
	assert.NotContains(t, view, "CryptoBOM")
}

func TestViewSummaryCapabilitiesBox(t *testing.T) {
	m := newTestModel()

	m.Update(matchFoundMsg{signatureID: "golang.filesystem.read", tags: []string{"capability", "filesystem"}, language: "go", filePath: "a.go"})
	m.Update(scanDoneMsg{err: nil})

	view := m.View()

	assert.Contains(t, view, "Language Capabilities")
	assert.Contains(t, view, "golang.filesystem.read")
	assert.NotContains(t, view, "AI BOM")
}

func TestViewSummaryMultipleCategoryBoxes(t *testing.T) {
	m := newTestModel()

	// AI matches
	m.Update(matchFoundMsg{signatureID: "openai.client", tags: []string{"ai", "llm"}, language: "python", filePath: "a.py"})
	// Crypto matches
	m.Update(matchFoundMsg{signatureID: "crypto.aes", tags: []string{"cryptography", "encryption"}, language: "go", filePath: "b.go"})
	// Capability matches
	m.Update(matchFoundMsg{signatureID: "golang.network.http", tags: []string{"capability", "network"}, language: "go", filePath: "c.go"})
	m.Update(scanDoneMsg{err: nil})

	view := m.View()

	assert.Contains(t, view, "AI BOM")
	assert.Contains(t, view, "CryptoBOM")
	assert.Contains(t, view, "Language Capabilities")
	assert.NotContains(t, view, "Cloud BOM") // no cloud matches

	// AI BOM should appear before CryptoBOM, which should appear before Capabilities
	aiIdx := strings.Index(view, "AI BOM")
	cryptoIdx := strings.Index(view, "CryptoBOM")
	capIdx := strings.Index(view, "Language Capabilities")

	assert.Greater(t, cryptoIdx, aiIdx, "AI BOM should appear before CryptoBOM")
	assert.Greater(t, capIdx, cryptoIdx, "CryptoBOM should appear before Language Capabilities")
}

func TestViewSummaryAllFourCategories(t *testing.T) {
	m := newTestModel()

	m.Update(matchFoundMsg{signatureID: "openai.client", tags: []string{"ai"}, language: "python", filePath: "a.py"})
	m.Update(matchFoundMsg{signatureID: "crypto.aes", tags: []string{"cryptography"}, language: "go", filePath: "b.go"})
	m.Update(matchFoundMsg{signatureID: "gcp.storage", tags: []string{"iaas"}, language: "python", filePath: "c.py"})
	m.Update(matchFoundMsg{signatureID: "golang.filesystem.read", tags: []string{"capability"}, language: "go", filePath: "d.go"})
	m.Update(scanDoneMsg{err: nil})

	view := m.View()

	assert.Contains(t, view, "AI BOM")
	assert.Contains(t, view, "CryptoBOM")
	assert.Contains(t, view, "Cloud BOM")
	assert.Contains(t, view, "Language Capabilities")

	// Verify priority ordering: AI < Crypto < Cloud < Capabilities
	aiIdx := strings.Index(view, "AI BOM")
	cryptoIdx := strings.Index(view, "CryptoBOM")
	cloudIdx := strings.Index(view, "Cloud BOM")
	capIdx := strings.Index(view, "Language Capabilities")

	assert.Greater(t, cryptoIdx, aiIdx)
	assert.Greater(t, cloudIdx, cryptoIdx)
	assert.Greater(t, capIdx, cloudIdx)
}

func TestGroupByCategoryTopFivePerCategory(t *testing.T) {
	m := newTestModel()

	// Add 7 AI signatures with decreasing counts
	aiSigs := []string{"ai.sig1", "ai.sig2", "ai.sig3", "ai.sig4", "ai.sig5", "ai.sig6", "ai.sig7"}
	for i, sig := range aiSigs {
		for j := 0; j < len(aiSigs)-i; j++ {
			m.Update(matchFoundMsg{signatureID: sig, tags: []string{"ai"}, language: "python", filePath: "x.py"})
		}
	}

	m.phase = phaseSummary
	content := m.buildCategoryContent("AI BOM", m.groupByCategory()[categoryAI])

	// Top 5 should be present
	for _, sig := range aiSigs[:5] {
		assert.Contains(t, content, sig)
	}
	// 6th and 7th should not
	assert.NotContains(t, content, "ai.sig6")
	assert.NotContains(t, content, "ai.sig7")
}

func TestBuildCategoryContentOrdering(t *testing.T) {
	m := newTestModel()

	for i := 0; i < 15; i++ {
		m.Update(matchFoundMsg{signatureID: "openai.client", tags: []string{"ai"}, language: "python", filePath: "a.py"})
	}
	for i := 0; i < 8; i++ {
		m.Update(matchFoundMsg{signatureID: "anthropic.client", tags: []string{"ai"}, language: "python", filePath: "b.py"})
	}
	for i := 0; i < 2; i++ {
		m.Update(matchFoundMsg{signatureID: "crewai.agent", tags: []string{"ai"}, language: "python", filePath: "c.py"})
	}

	m.phase = phaseSummary
	content := m.buildCategoryContent("AI BOM", m.groupByCategory()[categoryAI])

	openaiIdx := strings.Index(content, "openai.client")
	anthropicIdx := strings.Index(content, "anthropic.client")
	crewaiIdx := strings.Index(content, "crewai.agent")

	assert.Greater(t, anthropicIdx, openaiIdx)
	assert.Greater(t, crewaiIdx, anthropicIdx)
}
