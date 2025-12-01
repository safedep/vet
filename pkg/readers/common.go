package readers

import (
	"path/filepath"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/safedep/vet/pkg/common/logger"
)

const defaultApplicationName = "vet-scanned-project"

type exclusionMatcher struct {
	Exclusions []string
}

func newPathExclusionMatcher(exclusions []string) *exclusionMatcher {
	return &exclusionMatcher{
		Exclusions: exclusions,
	}
}

func (ex *exclusionMatcher) Match(term string) bool {
	for _, exclusionPattern := range ex.Exclusions {
		// Try matching in current form first
		if m, err := doublestar.Match(exclusionPattern, term); err == nil && m {
			return true
		}

		// If term is relative and pattern is absolute, convert term to absolute
		if !filepath.IsAbs(term) && filepath.IsAbs(exclusionPattern) {
			if abs, err := filepath.Abs(term); err == nil {
				if m, err := doublestar.Match(exclusionPattern, abs); err == nil && m {
					return true
				}
			}
		}

		// If term is absolute and pattern is relative, convert pattern to absolute
		if filepath.IsAbs(term) && !filepath.IsAbs(exclusionPattern) {
			if abs, err := filepath.Abs(exclusionPattern); err == nil {
				if m, err := doublestar.Match(abs, term); err == nil && m {
					return true
				}
			}
		}

		logger.Debugf("No match for pattern '%s' against '%s'", exclusionPattern, term)
	}

	return false
}
