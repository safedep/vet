package builtin

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/codeusage"
	"github.com/safedep/vet/v2/internal/plugins/sinks"
	"github.com/safedep/vet/v2/plugin"
)

func TestPluginsHaveUniqueSortedNames(t *testing.T) {
	var names []string
	for _, p := range Plugins() {
		names = append(names, p.Name)
	}
	assert.True(t, slices.IsSorted(names))
	assert.Len(t, slices.Compact(slices.Clone(names)), len(names), "no two plugins share a name")
	for _, want := range []string{"dependency-cooldown", "lockfile", "codeusage", "cloud-inventory", "tenant-policy", "cyclonedx"} {
		assert.Contains(t, names, want)
	}
	for _, none := range []string{"insights", "malysis"} {
		assert.NotContains(t, names, none, "vet reads no plugins.%s section", none)
	}
}

func TestPluginsCheckTheDefaultOptionsAndGiveASchema(t *testing.T) {
	for _, p := range Plugins() {
		t.Run(p.Name, func(t *testing.T) {
			require.NoError(t, p.Check(plugin.MapConfig(nil)))
			_, err := p.Schema()
			require.NoError(t, err)
		})
	}
}

func TestEachPluginSaysWhatItDoesAndHowItTurnsOn(t *testing.T) {
	formats := sinks.Builtin().Formats()
	for _, p := range Plugins() {
		t.Run(p.Name, func(t *testing.T) {
			assert.NotEmpty(t, p.Description)
			isFormat := slices.Contains(formats, p.Name)
			assert.Equal(t, !isFormat, p.Switch, "only a report format has no switch, because -o and --report select it")
			if isFormat {
				assert.False(t, p.On)
			}
		})
	}
}

func TestEnabledUsesTheBuiltInStateWhenNoLayerSetsIt(t *testing.T) {
	off := false
	cfg := config.Default()
	cfg.Plugins = map[string]config.PluginConfig{"vulnerability": {Enabled: &off}}
	cases := map[string]bool{
		"vulnerability": false,
		"workflow":      true,
		"codeusage":     codeusage.Available(),
		"tenant-policy": false,
	}
	for name, want := range cases {
		assert.Equal(t, want, Enabled(&cfg, name), name)
	}
	assert.Panics(t, func() { Enabled(&cfg, "nosuch") }, "a caller names a built-in plugin")
}
