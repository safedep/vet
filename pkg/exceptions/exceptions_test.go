package exceptions

import (
	"io"
	"testing"
	"time"

	"github.com/safedep/vet/gen/exceptionsapi"
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
