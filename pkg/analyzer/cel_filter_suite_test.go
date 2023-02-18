package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadFilterSuiteFromFile(t *testing.T) {
	cases := []struct {
		name         string
		path         string
		suiteName    string
		suiteDesc    string
		filtersCount int
		errMsg       string
	}{
		{
			"valid filter suite",
			"fixtures/filter_suite_valid.yml",
			"Valid Filter Suite",
			"Valid Filter Suite",
			1,
			"",
		},
		{
			"invalid filter suite",
			"fixtures/filter_suite_invalid.yml",
			"",
			"",
			0,
			"unknown field \"A\" in FilterSuite",
		},
		{
			"filter suite does not exists",
			"fixtures/filter_suite_does_not_exists.yml",
			"",
			"",
			0,
			"no such file or directory",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fs, err := loadFilterSuiteFromFile(test.path)
			if test.errMsg != "" {
				assert.NotNil(t, err)
				assert.ErrorContains(t, err, test.errMsg)
			} else {
				assert.Equal(t, test.suiteName, fs.GetName())
				assert.Equal(t, test.suiteDesc, fs.GetDescription())
				assert.Equal(t, test.filtersCount, len(fs.GetFilters()))
			}
		})
	}
}
