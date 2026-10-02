package report_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/plugins/cloud/report"
	"github.com/safedep/vet/v2/internal/plugins/sinks"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

func TestOptions(t *testing.T) {
	cases := []struct {
		name string
		opts map[string]any
		err  bool
	}{
		{name: "no options"},
		{name: "known options", opts: map[string]any{"upload": true, "project": "web"}},
		{name: "unknown option", opts: map[string]any{"bucket": "x"}, err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := report.New(plugin.MapConfig(tc.opts))
			if tc.err {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, s)
		})
	}
}

func TestStubRefusesToRun(t *testing.T) {
	_, err := sinks.Builtin().New(report.Name, nil)
	require.Error(t, err)
	ue, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, report.CodeUnavailable, ue.Code())
	assert.Equal(t, "the SafeDep Cloud report plugin is not available yet", ue.HumanError())
	assert.Equal(t, app.ExitUsage, app.ExitCode(err))

	s, err := report.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	var out bytes.Buffer
	assert.Error(t, s.Write(context.Background(), plugintest.SampleReport(), &out))
	assert.Zero(t, out.Len(), "the stub writes nothing")
}

func TestOptionsSchema(t *testing.T) {
	s, err := report.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	sc, ok := s.(plugin.Schemer)
	require.True(t, ok)
	var schema map[string]any
	require.NoError(t, json.Unmarshal(sc.OptionsSchema(), &schema))
	assert.Contains(t, schema["properties"], "upload")
	assert.Contains(t, schema["properties"], "project")
}
