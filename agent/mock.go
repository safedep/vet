package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/cloudwego/eino/schema"
)

// MockAgent provides a simple implementation of the Agent interface for testing
type mockAgent struct{}

// MockSession is a simple session implementation
type mockSession struct {
	sessionID string
	memory    Memory
}

type mockMemory struct {
	interactions []*schema.Message
}

func (m *mockMemory) AddInteraction(ctx context.Context, interaction *schema.Message) error {
	m.interactions = append(m.interactions, interaction)

	return nil
}

func (m *mockMemory) GetInteractions(ctx context.Context) ([]*schema.Message, error) {
	return m.interactions, nil
}

func (m *mockMemory) Clear(ctx context.Context) error {
	m.interactions = make([]*schema.Message, 0)

	return nil
}

// NewMockAgent creates a new mock agent
func NewMockAgent() *mockAgent {
	return &mockAgent{}
}

// NewMockSession creates a new mock session
func NewMockSession() *mockSession {
	return &mockSession{
		sessionID: "mock-session-1",
		memory:    &mockMemory{},
	}
}

func (s *mockSession) ID() string {
	return s.sessionID
}

func (s *mockSession) Memory() Memory {
	return s.memory
}

// Execute implements the Agent interface with mock responses
func (m *mockAgent) Execute(ctx context.Context, session Session, input Input) (Output, error) {
	// Simple mock responses based on input
	query := strings.ToLower(input.Query)

	var response string

	switch {
	case strings.Contains(query, "vulnerability") || strings.Contains(query, "vuln"):
		response = `🔍 **Vulnerability Analysis**

I found 3 critical vulnerabilities in your dependencies:

**Critical Issues:**
• lodash@4.17.19: CVE-2021-23337 (Command Injection)
• jackson-databind@2.9.8: CVE-2020-36518 (Deserialization)  
• urllib3@1.24.1: CVE-2021-33503 (SSRF)

**Recommendation:** Update these packages immediately. All have fixes available in newer versions.

Would you like me to analyze the impact of updating these packages?`

	case strings.Contains(query, "malware") || strings.Contains(query, "malicious"):
		response = `🚨 **Malware Detection Results**

I detected 2 potentially malicious packages:

**High Risk:**
• suspicious-package@1.0.0: Contains obfuscated code and cryptocurrency mining
• typosquatted-lib@2.1.0: Mimics popular library with malicious payload

**Action Required:** Remove these packages immediately and scan your systems.

Would you like me to suggest secure alternatives?`

	case strings.Contains(query, "secure") || strings.Contains(query, "security"):
		response = `🛡️ **Security Posture Assessment**

**Overall Security Score: 6.2/10 (Moderate Risk)**

**Summary:**
• 23 total security issues found
• 3 critical vulnerabilities requiring immediate action
• 2 malicious packages detected
• 15 packages with maintenance concerns

**Priority Actions:**
1. Remove malicious packages (Critical)
2. Update vulnerable dependencies (High)
3. Implement dependency scanning in CI/CD (Medium)

Would you like me to create a detailed remediation plan?`

	case strings.Contains(query, "update"):
		response = `⬆️ **Update Analysis**

Analyzing update recommendations for your dependencies...

**Safe Updates Available:**
• 12 packages can be safely updated (patch versions)
• 5 packages have minor version updates with new features
• 3 packages require major version updates (breaking changes)

**Priority Updates:**
1. lodash: 4.17.19 → 4.17.21 (Security fix, no breaking changes)
2. urllib3: 1.24.1 → 1.26.18 (Security fix, minimal risk)

Would you like detailed impact analysis for any specific package?`

	default:
		response = fmt.Sprintf(`🤖 **Security Analysis**

I'm analyzing your question about: "%s"

I have access to comprehensive security data including:
• Vulnerability databases
• Malware detection results  
• Dependency analysis
• License compliance
• Maintainer health metrics

**Available Analysis Types:**
• Security posture assessment
• Vulnerability impact analysis
• Malware detection
• Update recommendations
• Compliance checking

What specific aspect would you like me to analyze in detail?`, input.Query)
	}

	return Output{
		Answer: response,
		Format: AnswerFormatMarkdown,
	}, nil
}
