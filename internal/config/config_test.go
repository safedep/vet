package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault(t *testing.T) {
	c := Default()
	assert.Equal(t, "auto", c.Output.Mode)
	assert.Equal(t, 8, c.Scan.Concurrency)
	assert.Empty(t, c.Policy.FailOn, "the default has no gate")
	assert.Empty(t, c.Policy.File)
	assert.True(t, c.Cache.Enabled)
	assert.NotNil(t, c.Plugins)
}

func TestDuration(t *testing.T) {
	cases := []struct {
		in      Duration
		want    time.Duration
		wantErr bool
	}{
		{"", 0, false},
		{"24h", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"90m", 90 * time.Minute, false},
		{"x", 0, true},
		{"-1d", 0, true},
		{"-5m", 0, true},
	}
	for _, tc := range cases {
		got, err := tc.in.Value()
		if tc.wantErr {
			assert.Error(t, err, tc.in)
			continue
		}
		require.NoError(t, err, tc.in)
		assert.Equal(t, tc.want, got, tc.in)
	}
}

func TestByteSize(t *testing.T) {
	cases := []struct {
		in      ByteSize
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"2GB", 2 << 30, false},
		{"500mb", 500 << 20, false},
		{"10 KB", 10 << 10, false},
		{"42", 42, false},
		{"lots", 0, true},
		{"-1GB", 0, true},
	}
	for _, tc := range cases {
		got, err := tc.in.Bytes()
		if tc.wantErr {
			assert.Error(t, err, tc.in)
			continue
		}
		require.NoError(t, err, tc.in)
		assert.Equal(t, tc.want, got, tc.in)
	}
}

func TestPluginAccessors(t *testing.T) {
	off := false
	c := Default()
	c.Plugins["a"] = PluginConfig{Enabled: &off, Options: map[string]any{"days": 3}}

	assert.False(t, c.PluginEnabled("a", true))
	assert.True(t, c.PluginEnabled("b", true))
	assert.Equal(t, 3, c.PluginOptions("a")["days"])
	assert.NotNil(t, c.PluginOptions("b"))
}
