package reporter

import (
	"os"
	"testing"
)

func TestDetectTerminalCapability(t *testing.T) {
	tests := []struct {
		name           string
		envVars        map[string]string
		expectedCap    TerminalCapability
		description    string
	}{
		{
			name:        "NO_COLOR set",
			envVars:     map[string]string{"NO_COLOR": "1"},
			expectedCap: CapabilityNone,
			description: "Should disable colors when NO_COLOR is set",
		},
		{
			name:        "FORCE_COLOR 1",
			envVars:     map[string]string{"FORCE_COLOR": "1"},
			expectedCap: CapabilityANSI,
			description: "Should use ANSI colors when FORCE_COLOR=1",
		},
		{
			name:        "FORCE_COLOR 2",
			envVars:     map[string]string{"FORCE_COLOR": "2"},
			expectedCap: CapabilityANSI256,
			description: "Should use 256 colors when FORCE_COLOR=2",
		},
		{
			name:        "FORCE_COLOR 3",
			envVars:     map[string]string{"FORCE_COLOR": "3"},
			expectedCap: CapabilityTrueColor,
			description: "Should use true color when FORCE_COLOR=3",
		},
		{
			name:        "COLORTERM truecolor",
			envVars:     map[string]string{"COLORTERM": "truecolor", "FORCE_COLOR": "3"},
			expectedCap: CapabilityTrueColor,
			description: "Should detect true color from COLORTERM",
		},
		{
			name:        "COLORTERM 24bit",
			envVars:     map[string]string{"COLORTERM": "24bit", "FORCE_COLOR": "3"},
			expectedCap: CapabilityTrueColor,
			description: "Should detect true color from COLORTERM=24bit",
		},
		{
			name:        "TERM xterm-256color",
			envVars:     map[string]string{"TERM": "xterm-256color", "FORCE_COLOR": "2"},
			expectedCap: CapabilityANSI256,
			description: "Should detect 256 colors from TERM",
		},
		{
			name:        "TERM xterm",
			envVars:     map[string]string{"TERM": "xterm", "FORCE_COLOR": "1"},
			expectedCap: CapabilityANSI,
			description: "Should detect basic ANSI from TERM=xterm",
		},
		{
			name:        "NO_COLOR overrides COLORTERM",
			envVars:     map[string]string{"NO_COLOR": "1", "COLORTERM": "truecolor"},
			expectedCap: CapabilityNone,
			description: "NO_COLOR should take precedence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original env
			originalEnv := map[string]string{}
			for key := range tt.envVars {
				originalEnv[key] = os.Getenv(key)
			}

			// Clear relevant env vars first
			os.Unsetenv("NO_COLOR")
			os.Unsetenv("FORCE_COLOR")
			os.Unsetenv("COLORTERM")
			os.Unsetenv("TERM")

			// Set test env vars
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			// Run test
			config := detectTerminalCapability()

			if config.capability != tt.expectedCap {
				t.Errorf("%s: expected %v, got %v", tt.description, tt.expectedCap, config.capability)
			}

			// Restore original env
			for key, value := range originalEnv {
				if value == "" {
					os.Unsetenv(key)
				} else {
					os.Setenv(key, value)
				}
			}
			for key := range tt.envVars {
				if _, ok := originalEnv[key]; !ok {
					os.Unsetenv(key)
				}
			}
		})
	}
}

func TestColorFunctionsWithNO_COLOR(t *testing.T) {
	// Save original env
	originalNoColor := os.Getenv("NO_COLOR")
	defer func() {
		if originalNoColor == "" {
			os.Unsetenv("NO_COLOR")
		} else {
			os.Setenv("NO_COLOR", originalNoColor)
		}
		// Reinitialize global config
		globalColorConfig = detectTerminalCapability()
	}()

	// Set NO_COLOR
	os.Setenv("NO_COLOR", "1")
	config := detectTerminalCapability()

	testString := "test"

	tests := []struct {
		name     string
		function func(string) string
		input    string
		expected string
	}{
		{"CriticalBgText", config.CriticalBgText, testString, testString},
		{"CriticalText", config.CriticalText, testString, testString},
		{"HighBgText", config.HighBgText, testString, testString},
		{"MediumBgText", config.MediumBgText, testString, testString},
		{"LowBgText", config.LowBgText, testString, testString},
		{"WarningText", config.WarningText, testString, testString},
		{"WarningBgText", config.WarningBgText, testString, testString},
		{"SuccessBgText", config.SuccessBgText, testString, testString},
		{"InfoBgText", config.InfoBgText, testString, testString},
		{"InfoText", config.InfoText, testString, testString},
		{"MagentaBgText", config.MagentaBgText, testString, testString},
		{"WhiteBgText", config.WhiteBgText, testString, testString},
		{"FaintText", config.FaintText, testString, testString},
		{"BoldText", config.BoldText, testString, testString},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.function(tt.input)
			if result != tt.expected {
				t.Errorf("%s: with NO_COLOR, expected %q, got %q", tt.name, tt.expected, result)
			}
		})
	}
}

func TestColorFunctionsWithColors(t *testing.T) {
	// Save original env
	originalNoColor := os.Getenv("NO_COLOR")
	originalForceColor := os.Getenv("FORCE_COLOR")
	defer func() {
		if originalNoColor == "" {
			os.Unsetenv("NO_COLOR")
		} else {
			os.Setenv("NO_COLOR", originalNoColor)
		}
		if originalForceColor == "" {
			os.Unsetenv("FORCE_COLOR")
		} else {
			os.Setenv("FORCE_COLOR", originalForceColor)
		}
		// Reinitialize global config
		globalColorConfig = detectTerminalCapability()
	}()

	// Ensure colors are enabled
	os.Unsetenv("NO_COLOR")
	os.Setenv("FORCE_COLOR", "1")
	config := detectTerminalCapability()

	testString := "test"

	tests := []struct {
		name     string
		function func(string) string
	}{
		{"CriticalBgText", config.CriticalBgText},
		{"CriticalText", config.CriticalText},
		{"HighBgText", config.HighBgText},
		{"MediumBgText", config.MediumBgText},
		{"LowBgText", config.LowBgText},
		{"WarningText", config.WarningText},
		{"WarningBgText", config.WarningBgText},
		{"SuccessBgText", config.SuccessBgText},
		{"InfoBgText", config.InfoBgText},
		{"InfoText", config.InfoText},
		{"MagentaBgText", config.MagentaBgText},
		{"WhiteBgText", config.WhiteBgText},
		{"FaintText", config.FaintText},
		{"BoldText", config.BoldText},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.function(testString)
			// When colors are enabled, result should contain ANSI codes
			if result == testString {
				t.Errorf("%s: with colors enabled, expected colored output, got plain text", tt.name)
			}
			// Result should contain the original string
			if !containsString(result, testString) {
				t.Errorf("%s: result should contain original string %q, got %q", tt.name, testString, result)
			}
		})
	}
}

func TestGlobalColorFunctions(t *testing.T) {
	// Save original env
	originalNoColor := os.Getenv("NO_COLOR")
	defer func() {
		if originalNoColor == "" {
			os.Unsetenv("NO_COLOR")
		} else {
			os.Setenv("NO_COLOR", originalNoColor)
		}
		// Reinitialize global config
		globalColorConfig = detectTerminalCapability()
	}()

	// Set NO_COLOR to test global functions
	os.Setenv("NO_COLOR", "1")
	globalColorConfig = detectTerminalCapability()

	testString := "test"

	// Test that global functions work correctly
	if CriticalBgText(testString) != testString {
		t.Error("Global CriticalBgText should respect NO_COLOR")
	}
	if WarningText(testString) != testString {
		t.Error("Global WarningText should respect NO_COLOR")
	}
	if SuccessBgText(testString) != testString {
		t.Error("Global SuccessBgText should respect NO_COLOR")
	}
}

// Helper function to check if a string contains another string
// This is needed because colored output will have ANSI codes
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
