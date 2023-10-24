package analyzer

import (
	"testing"

	"github.com/safedep/vet/gen/checks"
	"github.com/safedep/vet/gen/filtersuite"
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
			2,
			"",
		},
		{
			"invalid filter suite",
			"fixtures/filter_suite_invalid.yml",
			"",
			"",
			0,
			"unknown field",
		},
		{
			"filter suite does not exists",
			"fixtures/filter_suite_does_not_exists.yml",
			"",
			"",
			0,
			"no such file or directory",
		},
		{
			"filter suite check type invalid",
			"fixtures/filter_suite_invalid_check_type.yml",
			"",
			"",
			0,
			"unknown value \"\\\"Invalid\\\"\"",
		},
		{
			"filter suite check type is missing",
			"fixtures/filter_suite_check_type_missing.yml",
			"Check Type Missing",
			"Filter Suite with Missing Check Type",
			1,
			"",
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

func TestFilterSuiteFilterParams(t *testing.T) {
	cases := []struct {
		name      string
		file      string
		filterIdx int
		assertFn  func(t *testing.T, filter *filtersuite.Filter)
	}{
		{
			"Filter has tag",
			"fixtures/filter_suite_valid.yml",
			0,
			func(t *testing.T, filter *filtersuite.Filter) {
				assert.Equal(t, 1, len(filter.GetTags()))
				assert.Equal(t, "A", filter.Tags[0])
			},
		},
		{
			"Filter has valid check type",
			"fixtures/filter_suite_valid.yml",
			1,
			func(t *testing.T, filter *filtersuite.Filter) {
				assert.Equal(t, checks.CheckType_CheckTypeVulnerability, filter.CheckType)
				assert.Equal(t, filter.Summary, "TEST SUMMARY")
				assert.Equal(t, filter.Description, "TEST DESCRIPTION")
			},
		},
		{
			"Filter with missing check type is unknown",
			"fixtures/filter_suite_check_type_missing.yml",
			0,
			func(t *testing.T, filter *filtersuite.Filter) {
				assert.Equal(t, checks.CheckType_CheckTypeUnknown, filter.CheckType)
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fs, err := loadFilterSuiteFromFile(test.file)
			assert.Nil(t, err)

			filter := fs.Filters[test.filterIdx]
			assert.NotNil(t, filter)

			test.assertFn(t, filter)
		})
	}
}
