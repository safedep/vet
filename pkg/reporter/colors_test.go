package reporter

import (
	"os"
	"testing"

	"github.com/charmbracelet/colorprofile"
)

func TestColorProfileDetection(t *testing.T) {
	// Simple test to ensure colorprofile integration works
	config := &ColorConfig{
		profile: colorprofile.Detect(os.Stdout, os.Environ()),
	}

	// Just verify we can call methods without panic
	_ = config.CriticalBgText("test")
	_ = config.WarningText("test")
}

func TestColorFunctionsWithNO_COLOR(t *testing.T) {
	// Test with NO_COLOR profile
	config := &ColorConfig{
		profile: colorprofile.NoTTY,
	}

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
	// Test with ANSI256 profile
	config := &ColorConfig{
		profile: colorprofile.ANSI256,
	}

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
	testString := "test"

	// Test that global functions work correctly (they use auto-detected profile)
	// We just verify they don't panic
	_ = CriticalBgText(testString)
	_ = WarningText(testString)
	_ = SuccessBgText(testString)
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
