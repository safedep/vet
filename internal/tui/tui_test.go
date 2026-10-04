package tui_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/stat"
)

func TestPassThroughWritesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	output.SetWriters(&stdout, &stderr)
	output.SetMode(output.Plain)
	t.Cleanup(func() { output.SetMode(output.Rich) })

	cases := []struct {
		name  string
		print func()
		want  string
	}{
		{name: "info", print: func() { tui.Info("read %d manifests", 3) }, want: "read 3 manifests"},
		{name: "warning", print: func() { tui.Warning("slow") }, want: "slow"},
		{name: "error", print: func() { tui.Error("failed") }, want: "failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stderr.Reset()
			tc.print()
			assert.Contains(t, stderr.String(), tc.want)
			assert.Empty(t, stdout.String())
		})
	}
}

func TestStatPlain(t *testing.T) {
	output.SetMode(output.Plain)
	t.Cleanup(func() { output.SetMode(output.Rich) })
	assert.Contains(t, stat.Render(stat.Card{Label: "Packages", Value: "12"}), "Packages")
}
