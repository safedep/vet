package readers

import (
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
		m, err := doublestar.Match(exclusionPattern, term)
		if err != nil {
			logger.Warnf("Invalid path pattern: %s: %v", exclusionPattern, err)
			continue
		}

		if m {
			return true
		}
	}

	return false
}
