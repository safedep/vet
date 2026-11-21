package view

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

var start = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

func TestSnapshotTextSaysWhatTheStageDoes(t *testing.T) {
	index := plugin.Work{Name: "code_index", Label: "Indexing the source code", Started: start, Budget: 5 * time.Minute}
	now := start.Add(2*time.Minute + 10*time.Second)
	cases := []struct {
		name string
		s    snapshot
		want string
	}{
		{"walk", snapshot{stage: engine.StageExtract, started: start, done: 41233, dir: "services/api"}, "Reading the manifests: 41233 files in 2m10s · services/api"},
		{"walk at the root", snapshot{stage: engine.StageExtract, started: start, done: 1}, "Reading the manifests: 1 file in 2m10s"},
		{"folder with a terminal escape", snapshot{stage: engine.StageExtract, started: start, done: 2, dir: "a\x1b]0;evil\x07b"}, "Reading the manifests: 2 files in 2m10s · a\\x1b]0;evil\\x07b"},
		{"endpoint", snapshot{kind: report.ScanKindEndpoint, stage: engine.StageExtract, started: start, done: 3}, "Reading the tools on this machine: 3 files in 2m10s"},
		{"wait for work", snapshot{stage: engine.StageEnrich, started: start, done: 4210, total: 6501, work: index}, "Indexing the source code: 2m10s of the 5m0s budget · 4210 of 6501 packages checked"},
		{"wait with no budget", snapshot{stage: engine.StageEnrich, started: start, work: plugin.Work{Name: "x", Label: "Working", Started: start}}, "Working: 2m10s"},
		{"work that ended", snapshot{stage: engine.StageEnrich, started: start, done: 3, total: 9, work: plugin.Work{Name: "x", Label: "Working", Done: true}}, "Checking 9 packages: 3 done in 2m10s"},
		{"work in the walk", snapshot{stage: engine.StageExtract, started: start, done: 5, work: index}, "Reading the manifests: 5 files in 2m10s"},
		{"checks", snapshot{stage: engine.StageEnrich, started: start, done: 3, total: 9}, "Checking 9 packages: 3 done in 2m10s"},
		{"evaluation", snapshot{stage: engine.StageEvaluate, started: start, done: 10, total: 2472}, "Evaluating the controls: 10 of 2472 manifests in 2m10s"},
		{"report", snapshot{stage: engine.StageReport, started: start}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.s.text(now))
		})
	}
}

func TestLineKindShowsAStatusWhileTheCountDoesNotMove(t *testing.T) {
	index := plugin.Work{Name: "code_index", Label: "Indexing the source code", Started: start}
	cases := []struct {
		name string
		s    snapshot
		want string
	}{
		{"walk", snapshot{stage: engine.StageExtract}, lineStatus},
		{"checks wait for work", snapshot{stage: engine.StageEnrich, total: 9, work: index}, lineStatus},
		{"checks", snapshot{stage: engine.StageEnrich, total: 9}, lineBar},
		{"checks with no count yet", snapshot{stage: engine.StageEnrich}, ""},
		{"evaluation", snapshot{stage: engine.StageEvaluate, total: 9}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.s.lineKind())
		})
	}
}

func TestWalkAndWorkUpdateTheShownText(t *testing.T) {
	v := newScan(Options{})
	t.Cleanup(v.Stop)
	index := plugin.Work{Name: "code_index", Label: "Indexing the source code", Started: start}
	search := plugin.Work{Name: "call_graph_search", Label: "Searching the call graph", Started: start}

	v.Stage(engine.StageExtract, 1, 4)
	v.Progress(engine.StageExtract, 1, 0)
	v.Walk("services/api/go.mod")
	assert.Equal(t, "services/api", v.snapshot().dir)
	v.Walk("go.mod")
	assert.Empty(t, v.snapshot().dir, "a file at the root has no folder")

	v.Stage(engine.StageEnrich, 2, 4)
	v.Walk("services/api/go.mod")
	assert.Empty(t, v.snapshot().dir, "the enrich stage reads no files")
	v.Work(index)
	v.Work(plugin.Work{Name: search.Name, Done: true})
	assert.Equal(t, index, v.snapshot().work, "the end of other work keeps the current work")
	v.Work(plugin.Work{Name: index.Name, Done: true})
	assert.Equal(t, plugin.Work{}, v.snapshot().work)
	assert.Equal(t, v.snapshot(), v.shown.s, "the live line reads the same state")
}

// beatClock returns a clock that the test moves.
func beatClock() (now func() time.Time, set func(d time.Duration)) {
	t := start
	return func() time.Time { return t }, func(d time.Duration) { t = start.Add(d) }
}

func TestBeatPrintsTheProgressOfALongStage(t *testing.T) {
	index := plugin.Work{Name: "code_index", Label: "Indexing the source code", Started: start, Budget: 5 * time.Minute}
	cases := []struct {
		name string
		mode output.Mode
		work bool
		want string
	}{
		{"plain", output.Plain, false, "[INFO] Checking 9 packages: 3 done in 16s"},
		{"plain wait", output.Plain, true, "[INFO] Indexing the source code: 16s of the 5m0s budget · 3 of 9 packages checked"},
		{"agent", output.Agent, false, "progress: enrich 3"},
		{"agent wait", output.Agent, true, "progress: enrich 3 work=code_index"},
		{"rich with no live line", output.Rich, false, "› Checking 9 packages: 3 done in 16s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := capture(t, tc.mode, func() {
				now, set := beatClock()
				v := NewScan(Options{})
				v.now = now
				defer v.Stop()
				v.Stage(engine.StageEnrich, 2, 4)
				v.Progress(engine.StageEnrich, 3, 9)
				if tc.work {
					v.Work(index)
				}
				set(10 * time.Second)
				v.beat()
				set(16 * time.Second)
				v.beat()
			})
			var lines []string
			for _, l := range strings.Split(strings.TrimSpace(got), "\n") {
				if !strings.HasPrefix(l, "INFO: scan started") {
					lines = append(lines, l)
				}
			}
			require.Len(t, lines, 1, "a stage shorter than %s gives no line", beatEvery)
			assert.Contains(t, lines[0], tc.want)
		})
	}
}

func TestBeatStopsWithTheView(t *testing.T) {
	got := capture(t, output.Plain, func() {
		now, set := beatClock()
		v := NewScan(Options{})
		v.now = now
		v.Stage(engine.StageExtract, 1, 4)
		v.Stop()
		set(time.Minute)
		v.beat()
		v.Stage(engine.StageEnrich, 2, 4)
		assert.Nil(t, v.beatStop, "a stopped view starts no heartbeat")
	})
	assert.NotContains(t, got, "Reading the manifests")
}

func TestBudgetStopComesRightAfterTheErrors(t *testing.T) {
	sample := plugintest.SampleReport()
	diags := []*report.Diagnostic{
		{Level: report.DiagnosticWarning, Code: report.CodeExtractFailed, Component: "extract", Message: "a: bad", Count: 1},
		{Level: report.DiagnosticWarning, Code: "module_graph", Component: "codeusage", Message: "no graph", Count: 1},
		{Level: report.DiagnosticWarning, Code: report.CodeReachStopped, Component: "codeusage", Message: "search stopped", Count: 1},
		{Level: report.DiagnosticError, Code: report.CodeEnrichFailed, Component: "malysis", Message: "unavailable", Count: 1},
		{Level: report.DiagnosticWarning, Code: report.CodeSourceFileMissing, Component: "codeusage", Message: "index stopped", Count: 1},
	}
	got := capture(t, output.Plain, func() {
		NewScan(Options{Saved: true}).diagnostics(sample.Header(), diags)
	})
	lines := strings.Split(strings.TrimSpace(got), "\n")
	require.Len(t, lines, 5)
	for i, want := range []string{"unavailable", "search stopped", "index stopped", "a: bad", "no graph"} {
		assert.Contains(t, lines[i], want)
	}
}
