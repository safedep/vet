package sinks

import (
	"context"
	"io"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/plugin"
)

type nopSink struct{ opt string }

func (nopSink) Write(context.Context, plugin.Report, io.Writer) error { return nil }

func spec(name string) Spec {
	return Spec{Name: name, New: func(cfg plugin.Config) (plugin.Sink, error) {
		var o struct {
			Opt string `json:"opt"`
		}
		if err := cfg.Decode(&o); err != nil {
			return nil, err
		}
		return nopSink{opt: o.Opt}, nil
	}}
}

type nopPublisher struct{ nopSink }

func (nopPublisher) Publish(context.Context, plugin.Report) (string, error) { return "", nil }

var reg = Registry{
	spec("json"), spec("plain"),
	{Name: "pr-comment", Publishes: true, New: func(plugin.Config) (plugin.Sink, error) { return nopPublisher{}, nil }},
	spec("sarif"), spec("table"),
}

func TestDestinations(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		reports []string
		mode    output.Mode
		want    []Destination
		wantErr string
	}{
		{name: "rich default", mode: output.Rich, want: []Destination{{Format: "table"}}},
		{name: "plain default", mode: output.Plain, want: []Destination{{Format: "plain"}}},
		{name: "agent default", mode: output.Agent, want: []Destination{{Format: "json"}}},
		{name: "-o", out: "sarif", mode: output.Agent, want: []Destination{{Format: "sarif"}}},
		{
			name: "reports", out: "table", reports: []string{"json=vet.json", "sarif=out/vet.sarif", "table=findings.txt"},
			want: []Destination{{Format: "table"}, {Format: "json", Path: "vet.json"}, {Format: "sarif", Path: "out/vet.sarif"}, {Format: "table", Path: "findings.txt"}},
		},
		{name: "unknown -o", out: "xml", wantErr: `-o: unknown format "xml"`},
		{name: "a path in -o", out: "vet.json", wantErr: "unknown format"},
		{name: "no path", out: "table", reports: []string{"json="}, wantErr: "use FORMAT=PATH"},
		{name: "no format", out: "table", reports: []string{"vet.json"}, wantErr: "use FORMAT=PATH"},
		{name: "unknown report format", out: "table", reports: []string{"xml=a.xml"}, wantErr: `unknown format "xml"`},
		{name: "same path twice", out: "table", reports: []string{"json=a", "sarif=a"}, wantErr: "another --report writes a"},
		{
			name: "publish", out: "table", reports: []string{"pr-comment", "pr-comment=body.md"},
			want: []Destination{{Format: "table"}, {Format: "pr-comment", Publish: true}, {Format: "pr-comment", Path: "body.md"}},
		},
		{name: "publish twice", out: "table", reports: []string{"pr-comment", "pr-comment"}, wantErr: "another --report publishes pr-comment"},
		{name: "no path for a file format", out: "table", reports: []string{"json"}, wantErr: "use FORMAT=PATH"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := reg.Destinations(tc.out, tc.reports, tc.mode)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				ue, ok := usefulerror.AsUsefulError(err)
				require.True(t, ok)
				assert.Equal(t, CodeOutput, ue.Code())
				assert.Contains(t, ue.Help(), "json, plain, pr-comment, sarif, table")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNew(t *testing.T) {
	s, err := reg.New("json", plugin.MapConfig{"opt": "x"})
	require.NoError(t, err)
	assert.Equal(t, nopSink{opt: "x"}, s)

	_, err = reg.New("json", nil)
	require.NoError(t, err)
	_, err = reg.New("json", plugin.MapConfig{"nope": 1})
	assert.ErrorContains(t, err, "plugins.json.options")
	_, err = reg.New("xml", nil)
	assert.Error(t, err)
}

func TestBuiltinIsSortedAndUnique(t *testing.T) {
	formats := Builtin().Formats()
	assert.IsIncreasing(t, formats)
}

func TestBuiltinPublishesMatchesTheSink(t *testing.T) {
	for _, s := range Builtin() {
		sink, err := s.New(plugin.MapConfig(nil))
		require.NoError(t, err, s.Name)
		_, ok := sink.(plugin.Publisher)
		assert.Equal(t, ok, s.Publishes, "format %s: Spec.Publishes must match plugin.Publisher", s.Name)
	}
}
