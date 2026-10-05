package controls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type settings struct {
	enabled map[string]bool
	options map[string]map[string]any
}

func (s settings) PluginEnabled(name string, def bool) bool {
	if v, ok := s.enabled[name]; ok {
		return v
	}
	return def
}

func (s settings) PluginOptions(name string) map[string]any {
	if o, ok := s.options[name]; ok {
		return o
	}
	return map[string]any{}
}

func names(cs []Control) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

func TestBuild(t *testing.T) {
	cases := []struct {
		name    string
		s       settings
		want    []string
		wantErr string
	}{
		{name: "defaults", want: []string{"agent-config", "dependency-cooldown", "hygiene", "license", "lockfile", "malware", "reputation", "vulnerability", "workflow"}},
		{name: "disabled", s: settings{enabled: map[string]bool{"malware": false}}, want: []string{"agent-config", "dependency-cooldown", "hygiene", "license", "lockfile", "reputation", "vulnerability", "workflow"}},
		{name: "options", s: settings{options: map[string]map[string]any{"malware": {"trust_automated_analysis": true}}}, want: []string{"agent-config", "dependency-cooldown", "hygiene", "license", "lockfile", "malware", "reputation", "vulnerability", "workflow"}},
		{name: "bad options", s: settings{options: map[string]map[string]any{"lockfile": {"nope": 1}}}, wantErr: "plugins.lockfile.options"},
		{name: "bad license", s: settings{options: map[string]map[string]any{"license": {"deny": []any{"GPL"}}}}, wantErr: `plugins.license.options: license: deny: ["GPL"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Build(tc.s)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, names(got))
		})
	}
}

func TestBuiltinIsSorted(t *testing.T) {
	var prev string
	for _, s := range Builtin() {
		assert.Less(t, prev, s.Name)
		prev = s.Name
	}
}
