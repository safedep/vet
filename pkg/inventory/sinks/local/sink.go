// Package local implements an in-process inventory.Sink that
// accumulates emitted items, renders the same end-of-scan summary table
// vet's `ai discover` command produces today, and optionally writes the
// raw item list as JSON to disk.
//
// The sink is single-goroutine and not safe for concurrent use; the
// inventory orchestrator drives sinks serially.
package local

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/inventory"
)

// Metadata keys mirror the canonical names produced by the aitool
// adapter (see pkg/inventory/scanners/aitool/translate.go). Duplicating
// the constants here keeps LocalSink free of a build-time dep on the
// adapter package; the contract is the metadata schema, not the symbol.
const (
	metaKeyAppDisplay       = "app.display"
	metaKeyBinaryVersion    = "binary.version"
	metaKeyBinaryPath       = "binary.path"
	metaKeyExtensionID      = "extension.id"
	metaKeyExtensionVersion = "extension.version"
	metaKeyExtensionIDE     = "extension.ide"
)

// reportFileMode is the permission bits applied to the JSON report
// file, matching the existing `cmd/ai/discover.go` writer.
const reportFileMode os.FileMode = 0o644

// Option configures a LocalSink at construction.
type Option func(*LocalSink)

// WithReportJSON instructs the sink to marshal the accumulated items as
// JSON to path during End. An empty path disables the report.
func WithReportJSON(path string) Option {
	return func(s *LocalSink) { s.reportPath = path }
}

// WithSilent suppresses the end-of-scan summary table render.
func WithSilent() Option {
	return func(s *LocalSink) { s.silent = true }
}

// WithOutput overrides the writer used for the table render. Defaults
// to os.Stderr — exposed for tests so they can capture the rendered
// output without touching the process stderr.
func WithOutput(w io.Writer) Option {
	return func(s *LocalSink) { s.output = w }
}

// LocalSink is an in-memory inventory.Sink. It buffers every Emit call
// in registration order and, on End, renders a summary table and
// optionally writes a JSON report.
//
// Construction defaults: output to os.Stderr, no JSON report, table
// render enabled.
type LocalSink struct {
	output     io.Writer
	silent     bool
	reportPath string

	// items accumulates every emitted item in scan order. Bounded
	// only by the number of items the active scanners produce; for
	// AI-tool scans this is dozens. A future filesystem OSS scanner
	// will need to revisit this (stream JSON, bound the buffer).
	items []*inventory.Item
}

// New constructs a LocalSink with the supplied options.
func New(opts ...Option) *LocalSink {
	s := &LocalSink{
		output: os.Stderr,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Items returns the accumulated items. Exposed for inspection by the
// cmd layer (e.g. when `--report-json` is wired up to LocalSink) and
// for tests; the slice is not safe to mutate.
func (s *LocalSink) Items() []*inventory.Item {
	return s.items
}

// Begin resets the in-memory buffer for a new scan. It performs no I/O.
func (s *LocalSink) Begin(_ context.Context, _ *inventory.Session) error {
	s.items = nil
	return nil
}

// Emit appends an item to the in-memory buffer.
func (s *LocalSink) Emit(_ context.Context, item *inventory.Item) error {
	s.items = append(s.items, item)
	return nil
}

// End renders the summary table (unless WithSilent was set) and writes
// the JSON report (when WithReportJSON was set). The summary argument
// is currently unused by LocalSink — TotalObserved is rederived from
// the buffered items so the table count exactly matches the rendered
// rows even if a sink ahead of LocalSink dropped items.
func (s *LocalSink) End(_ context.Context, _ *inventory.ScanSummary) error {
	if !s.silent {
		s.renderTable()
	}
	if s.reportPath != "" {
		if err := writeJSON(s.reportPath, s.items); err != nil {
			return fmt.Errorf("local sink: write json report: %w", err)
		}
	}
	return nil
}

// Close releases the buffered items so they are eligible for GC.
func (s *LocalSink) Close(_ context.Context) error {
	s.items = nil
	return nil
}

// renderTable emits the discovery summary table to the configured
// writer, preserving the column layout and styling vet's
// `ai discover` command produces today
// (TYPE | NAME | APP | SCOPE | DETAIL).
func (s *LocalSink) renderTable() {
	apps := countDistinctApps(s.items)
	if _, err := fmt.Fprintf(s.output, "\nDiscovered %d AI tool usage(s) across %d app(s)\n\n", len(s.items), apps); err != nil {
		logger.Warnf("local sink: write header: %v", err)
	}

	if len(s.items) == 0 {
		return
	}

	tbl := table.NewWriter()
	tbl.SetOutputMirror(s.output)
	tbl.SetStyle(table.StyleLight)
	tbl.AppendHeader(table.Row{"TYPE", "NAME", "APP", "SCOPE", "DETAIL"})

	for _, item := range s.items {
		tbl.AppendRow(table.Row{
			kindDisplayName(item.Kind),
			item.Name,
			appDisplay(item),
			scopeDisplayName(item.Scope),
			itemDetail(item),
		})
	}

	tbl.Render()
	if _, err := fmt.Fprintln(s.output); err != nil {
		logger.Warnf("local sink: write footer: %v", err)
	}
}

// countDistinctApps counts unique App values in the buffered items,
// using the canonical App field (not the display variant) as the key.
func countDistinctApps(items []*inventory.Item) int {
	if len(items) == 0 {
		return 0
	}
	seen := make(map[string]struct{}, len(items))
	for _, it := range items {
		seen[it.App] = struct{}{}
	}
	return len(seen)
}

// appDisplay prefers the human-friendly app.display metadata when
// present, falling back to the canonical app name. Mirrors the
// AppDisplay column in `cmd/ai/discover.go`.
func appDisplay(item *inventory.Item) string {
	if v, ok := item.Metadata[metaKeyAppDisplay]; ok && v != "" {
		return v
	}
	return item.App
}

// kindDisplayName returns the human-friendly label rendered in the TYPE
// column. Mirrors aitool.AIToolType.DisplayName so tables produced via
// either path are visually identical.
func kindDisplayName(k inventory.Kind) string {
	switch k {
	case inventory.KindMCPServer:
		return "MCP Server"
	case inventory.KindCodingAgent:
		return "Coding Agent"
	case inventory.KindAIExtension:
		return "AI Extension"
	case inventory.KindCLITool:
		return "CLI Tool"
	case inventory.KindProjectConfig:
		return "Project Config"
	case inventory.KindBrowserExtension:
		return "Browser Extension"
	case inventory.KindIDEExtension:
		return "IDE Extension"
	case inventory.KindAgentPlugin:
		return "Agent Plugin"
	case inventory.KindAgentSkill:
		return "Agent Skill"
	default:
		return "Unspecified"
	}
}

// scopeDisplayName returns the human-friendly label for the SCOPE
// column. Mirrors aitool.AIToolScope.DisplayName.
func scopeDisplayName(s inventory.Scope) string {
	switch s {
	case inventory.ScopeSystem:
		return "System"
	case inventory.ScopeProject:
		return "Project"
	default:
		return ""
	}
}

// itemDetail computes the kind-specific DETAIL column. Pure function so
// it can be exercised independently in tests. Mirrors `toolDetail` from
// `cmd/ai/discover.go`, adapted to read from inventory.Item instead of
// aitool.AITool.
func itemDetail(item *inventory.Item) string {
	switch item.Kind {
	case inventory.KindMCPServer:
		return mcpServerDetail(item)
	case inventory.KindCLITool:
		return cliToolDetail(item)
	case inventory.KindAIExtension:
		return aiExtensionDetail(item)
	case inventory.KindProjectConfig:
		return projectConfigDetail(item)
	default:
		return item.ConfigPath
	}
}

func mcpServerDetail(item *inventory.Item) string {
	if item.MCPServer == nil {
		return item.ConfigPath
	}
	transport := transportLabel(item.MCPServer.Transport)
	if item.MCPServer.Command != "" {
		out := transport + ": " + item.MCPServer.Command
		for _, arg := range item.MCPServer.Args {
			out += " " + arg
		}
		return out
	}
	if item.MCPServer.URL != "" {
		return transport + ": " + item.MCPServer.URL
	}
	return item.ConfigPath
}

// transportLabel returns the wire-string label for a transport,
// matching aitool.MCPTransport's lowercase form so the rendered detail
// column reads identically to the legacy `ai discover` output.
func transportLabel(t inventory.Transport) string {
	switch t {
	case inventory.TransportStdio:
		return "stdio"
	case inventory.TransportSSE:
		return "sse"
	case inventory.TransportStreamableHTTP:
		return "streamable_http"
	default:
		return ""
	}
}

func cliToolDetail(item *inventory.Item) string {
	version := item.Metadata[metaKeyBinaryVersion]
	path := item.Metadata[metaKeyBinaryPath]
	if version != "" {
		return path + " v" + version
	}
	return path
}

func aiExtensionDetail(item *inventory.Item) string {
	id := item.Metadata[metaKeyExtensionID]
	version := item.Metadata[metaKeyExtensionVersion]
	ide := item.Metadata[metaKeyExtensionIDE]
	detail := id
	if version != "" {
		detail += " v" + version
	}
	if ide != "" {
		detail += " (" + ide + ")"
	}
	return detail
}

func projectConfigDetail(item *inventory.Item) string {
	if item.Agent != nil && len(item.Agent.InstructionFiles) > 0 {
		names := make([]string, len(item.Agent.InstructionFiles))
		for i, p := range item.Agent.InstructionFiles {
			names[i] = filepath.Base(p)
		}
		return strings.Join(names, ", ")
	}
	return item.ConfigPath
}

// writeJSON marshals items with two-space indent and writes them to
// path with reportFileMode. Mirrors the existing `writeJSONInventory`
// in `cmd/ai/discover.go` so consumers see the same format.
func writeJSON(path string, items []*inventory.Item) error {
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, reportFileMode)
}
