package exceptions

import (
	"io"
	"testing"
	"time"

	"github.com/safedep/vet/gen/exceptionsapi"
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

type exceptionsLoaderMocker struct {
	rules []exceptionRule
	idx   int
}

func (m *exceptionsLoaderMocker) Read() (*exceptionRule, error) {
	if m.idx >= len(m.rules) {
		return nil, io.EOF
	}

	r := m.rules[m.idx]
	m.idx += 1

	return &r, nil
}

func TestLoad(t *testing.T) {
	cases := []struct {
		name   string
		rules  []exceptionRule
		pCount int // Package count
	}{
		{
			"Load a rule",
			[]exceptionRule{
				{
					spec: &exceptionsapi.Exception{
						Id:        "a",
						Ecosystem: "maven",
						Name:      "p1",
					},
					expiry: time.Now().Add(1 * time.Hour),
				},
			},
			1,
		},
		{
			"Load two rule for same package",
			[]exceptionRule{
				{
					spec: &exceptionsapi.Exception{
						Id:        "a",
						Ecosystem: "maven",
						Name:      "p1",
					},
					expiry: time.Now().Add(1 * time.Hour),
				},
				{
					spec: &exceptionsapi.Exception{
						Id:        "b",
						Ecosystem: "maven",
						Name:      "p1",
					},
					expiry: time.Now().Add(1 * time.Hour),
				},
			},
			1,
		},
		{
			"Load two rule for two package",
			[]exceptionRule{
				{
					spec: &exceptionsapi.Exception{
						Id:        "a",
						Ecosystem: "maven",
						Name:      "p1",
					},
					expiry: time.Now().Add(1 * time.Hour),
				},
				{
					spec: &exceptionsapi.Exception{
						Id:        "b",
						Ecosystem: "maven",
						Name:      "p2",
					},
					expiry: time.Now().Add(1 * time.Hour),
				},
			},
			2,
		},
		{
			"Load an expired rule",
			[]exceptionRule{
				{
					spec: &exceptionsapi.Exception{
						Id:        "a",
						Ecosystem: "maven",
						Name:      "p1",
					},
					expiry: time.Now().Add(-1 * time.Hour),
				},
			},
			0,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			// Reset the store
			initStore()

			Load(&exceptionsLoaderMocker{
				rules: test.rules,
			})

			assert.Equal(t, test.pCount, len(globalExceptions.rules))
		})
	}
}

func TestApply(t *testing.T) {
	cases := []struct {
		name      string
		rules     []exceptionRule
		ecosystem string
		pkgName   string
		version   string
		match     bool
		errMsg    string
	}{
		{
			"Match by version",
			[]exceptionRule{
				{
					spec: &exceptionsapi.Exception{
						Id:        "a",
						Ecosystem: "maven",
						Name:      "p1",
						Version:   "v1",
					},
					expiry: time.Now().Add(1 * time.Hour),
				},
			},
			"maven",
			"p1",
			"v1",
			true,
			"",
		},
		{
			"Match any version",
			[]exceptionRule{
				{
					spec: &exceptionsapi.Exception{
						Id:        "a",
						Ecosystem: "maven",
						Name:      "p1",
						Version:   "*",
					},
					expiry: time.Now().Add(1 * time.Hour),
				},
			},
			"maven",
			"p1",
			"v-anything",
			true,
			"",
		},
		{
			"No Match without a version",
			[]exceptionRule{
				{
					spec: &exceptionsapi.Exception{
						Id:        "a",
						Ecosystem: "maven",
						Name:      "p1",
						Version:   "",
					},
					expiry: time.Now().Add(1 * time.Hour),
				},
			},
			"maven",
			"p1",
			"v-anything",
			false,
			"",
		},
		{
			"Match with case-insensitive",
			[]exceptionRule{
				{
					spec: &exceptionsapi.Exception{
						Id:        "a",
						Ecosystem: "MAVEN",
						Name:      "P1",
						Version:   "v1",
					},
					expiry: time.Now().Add(1 * time.Hour),
				},
			},
			"maven",
			"p1",
			"v1",
			true,
			"",
		},
		{
			"No match with case-insensitive version",
			[]exceptionRule{
				{
					spec: &exceptionsapi.Exception{
						Id:        "a",
						Ecosystem: "MAVEN",
						Name:      "P1",
						Version:   "V1",
					},
					expiry: time.Now().Add(1 * time.Hour),
				},
			},
			"maven",
			"p1",
			"v1",
			false,
			"",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			initStore()

			Load(&exceptionsLoaderMocker{
				rules: test.rules,
			})

			pd := models.NewPackageDetail(test.ecosystem, test.pkgName, test.version)
			res, err := Apply(&models.Package{
				PackageDetails: pd,
			})

			if test.errMsg != "" {
				assert.NotNil(t, err)
				assert.ErrorContains(t, err, test.errMsg)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, test.match, res.Matched())
			}
		})
	}
}
