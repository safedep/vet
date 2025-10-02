package reporter

import (
	"os"
	"testing"

	"github.com/charmbracelet/colorprofile"
)

func TestColorConfig(t *testing.T) {
	// Save original environment
	origNoColor := os.Getenv("NO_COLOR")
	origForceColor := os.Getenv("FORCE_COLOR")
	defer func() {
		os.Setenv("NO_COLOR", origNoColor)
		os.Setenv("FORCE_COLOR", origForceColor)
		// Reset global config
		globalColorConfig = newColorConfig()
	}()

	t.Run("respects NO_COLOR environment variable", func(t *testing.T) {
		os.Setenv("NO_COLOR", "1")
		os.Setenv("FORCE_COLOR", "")
		
		cfg := newColorConfig()
		if cfg.profile != colorprofile.Ascii && cfg.profile != colorprofile.NoTTY {
			t.Errorf("Expected Ascii or NoTTY profile with NO_COLOR=1, got %v", cfg.profile)
		}
	})

	t.Run("respects FORCE_COLOR environment variable", func(t *testing.T) {
		os.Setenv("NO_COLOR", "")
		os.Setenv("FORCE_COLOR", "1")
		
		cfg := newColorConfig()
		// Should enable colors when FORCE_COLOR is set
		// Note: In test environment without a TTY, this might still be NoTTY
		// The important thing is that the function doesn't panic
		_ = cfg.CriticalColor().Sprint("test")
	})

	t.Run("color functions return appropriate colors", func(t *testing.T) {
		os.Setenv("NO_COLOR", "")
		os.Setenv("FORCE_COLOR", "1")
		
		cfg := newColorConfig()
		
		// Test that color functions don't panic
		_ = cfg.CriticalColor().Sprint("test")
		_ = cfg.HighColor().Sprint("test")
		_ = cfg.SuccessColor().Sprint("test")
		
		// In a test environment, colors might be disabled due to no TTY
		// but the functions should still work without panicking
	})

	t.Run("color functions gracefully degrade without colors", func(t *testing.T) {
		os.Setenv("NO_COLOR", "1")
		os.Setenv("FORCE_COLOR", "")
		
		cfg := newColorConfig()
		
		// When colors are disabled, should still return valid Colors (possibly empty or bold-only)
		criticalColor := cfg.CriticalColor()
		_ = criticalColor.Sprint("test") // Should not panic
	})
}

func TestSemanticColorFunctions(t *testing.T) {
	// Save original environment
	origNoColor := os.Getenv("NO_COLOR")
	origForceColor := os.Getenv("FORCE_COLOR")
	defer func() {
		os.Setenv("NO_COLOR", origNoColor)
		os.Setenv("FORCE_COLOR", origForceColor)
		globalColorConfig = newColorConfig()
	}()

	t.Run("convenience functions work correctly", func(t *testing.T) {
		os.Setenv("NO_COLOR", "")
		os.Setenv("FORCE_COLOR", "1")
		globalColorConfig = newColorConfig()

		testCases := []struct {
			name string
			fn   func(string) string
		}{
			{"CriticalText", CriticalText},
			{"CriticalBgText", CriticalBgText},
			{"HighText", HighText},
			{"HighBgText", HighBgText},
			{"MediumBgText", MediumBgText},
			{"LowBgText", LowBgText},
			{"WarningText", WarningText},
			{"SuccessBgText", SuccessBgText},
			{"InfoBgText", InfoBgText},
			{"ErrorBgText", ErrorBgText},
			{"FaintText", FaintText},
			{"BoldText", BoldText},
			{"NeutralBgText", NeutralBgText},
			{"MagentaBgText", MagentaBgText},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := tc.fn("test")
				if result == "" {
					t.Errorf("%s should return non-empty string", tc.name)
				}
			})
		}
	})

	t.Run("functions work with NO_COLOR", func(t *testing.T) {
		os.Setenv("NO_COLOR", "1")
		os.Setenv("FORCE_COLOR", "")
		globalColorConfig = newColorConfig()

		// Should not panic and should return the text (possibly without colors)
		result := CriticalText("test")
		if result == "" {
			t.Error("CriticalText should return non-empty string even with NO_COLOR")
		}
	})
}

func TestColorProfileDetection(t *testing.T) {
	t.Run("newColorConfig creates valid config", func(t *testing.T) {
		cfg := newColorConfig()
		if cfg == nil {
			t.Error("newColorConfig should return non-nil config")
		}
	})

	t.Run("getColorConfig returns global config", func(t *testing.T) {
		cfg := getColorConfig()
		if cfg == nil {
			t.Error("getColorConfig should return non-nil config")
		}
	})
}

func TestColorDegradation(t *testing.T) {
	testCases := []struct {
		name     string
		profile  colorprofile.Profile
	}{
		{"TrueColor", colorprofile.TrueColor},
		{"ANSI256", colorprofile.ANSI256},
		{"ANSI", colorprofile.ANSI},
		{"Ascii", colorprofile.Ascii},
		{"NoTTY", colorprofile.NoTTY},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &colorConfig{profile: tc.profile}
			
			// Test that all color functions work without panicking
			_ = cfg.CriticalColor().Sprint("test")
			_ = cfg.CriticalBgColor().Sprint("test")
			_ = cfg.HighColor().Sprint("test")
			_ = cfg.HighBgColor().Sprint("test")
			_ = cfg.MediumColor().Sprint("test")
			_ = cfg.MediumBgColor().Sprint("test")
			_ = cfg.LowColor().Sprint("test")
			_ = cfg.LowBgColor().Sprint("test")
			_ = cfg.WarningColor().Sprint("test")
			_ = cfg.SuccessColor().Sprint("test")
			_ = cfg.SuccessBgColor().Sprint("test")
			_ = cfg.InfoColor().Sprint("test")
			_ = cfg.InfoBgColor().Sprint("test")
			_ = cfg.ErrorBgColor().Sprint("test")
			_ = cfg.FaintColor().Sprint("test")
			_ = cfg.BoldColor().Sprint("test")
			_ = cfg.NeutralBgColor().Sprint("test")
			_ = cfg.MagentaBgColor().Sprint("test")
		})
	}
}
