package tenantpolicy_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/cloud/tenantpolicy"
	"github.com/safedep/vet/v2/plugin"
)

func TestStub(t *testing.T) {
	cases := []struct {
		name string
		opts map[string]any
		err  bool
	}{
		{name: "no options"},
		{name: "a named policy", opts: map[string]any{"policy": "strict"}},
		{name: "unknown option", opts: map[string]any{"url": "x"}, err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, err := tenantpolicy.New(plugin.MapConfig(tc.opts))
			if tc.err {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			docs, err := src.Policies(context.Background())
			assert.ErrorIs(t, err, plugin.ErrUnavailable)
			assert.Empty(t, docs)
			_, ok := src.(plugin.Schemer)
			assert.True(t, ok)
		})
	}
}
