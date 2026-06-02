// Package endpoint hosts the `vet endpoint` cobra subcommand tree. The
// scan subcommand wires the inventory pipeline (pkg/inventory) into the
// CLI: scanners discover endpoint inventory, sinks render it locally and
// (when credentials are configured) ship it to SafeDep Cloud via
// endpointsync.
package endpoint

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	drygrpc "github.com/safedep/dry/adapters/grpc"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/command"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/inventory"
	"github.com/safedep/vet/pkg/inventory/scanners"
	cloudsink "github.com/safedep/vet/pkg/inventory/sinks/cloud"
	localsink "github.com/safedep/vet/pkg/inventory/sinks/local"
)

// DefaultDrainTimeout is the default `--drain-timeout` value and the
// fallback applied when Options.DrainTimeout is zero.
const DefaultDrainTimeout = 30 * time.Second

// Options is the public surface common to `vet endpoint scan` and the
// aliases that re-export it. cobra binds this directly. Aliases that
// pin a specific scanner kind (e.g. RunAITool) overwrite Options.Kinds
// before invoking the shared pipeline; callers of an alias entrypoint
// do not need to set Kinds; it is overwritten.
type Options struct {
	// Scopes restricts discovery to a subset of inventory scopes; nil
	// means "all scopes enabled" (mirrors aitool.DiscoveryConfig).
	Scopes []string
	// ProjectDir overrides the project root for project-scoped scans;
	// empty defaults to the process's cwd.
	ProjectDir string
	// ReportJSON, when non-empty, instructs LocalSink to marshal the
	// accumulated items to the supplied path on End.
	ReportJSON string
	// Silent suppresses the local table render at end-of-scan.
	Silent bool
	// Kinds is the scanner-kind allowlist; nil/empty means "all
	// registered kinds". Set directly by `vet endpoint scan`'s --kind
	// flag; overwritten by alias entrypoints.
	Kinds []string
	// DrainTimeout bounds CloudSink.Close's wait for pending events to
	// ship. Zero falls back to DefaultDrainTimeout.
	DrainTimeout time.Duration
}

// RunAITool runs the endpoint-scan pipeline pinned to the ai-tool kind.
// It is the integration point for cmd/ai/discover; opts.Kinds is
// overwritten.
func RunAITool(ctx context.Context, opts Options) error {
	return runAIToolWithRunner(ctx, opts, runScan)
}

// runAIToolWithRunner is the testable core of RunAITool. It pins the ai-tool
// kinds and delegates to run, allowing tests to intercept without swapping
// the package-level runScan.
func runAIToolWithRunner(ctx context.Context, opts Options, run scanRunner) error {
	opts.Kinds = []string{
		scanners.KindAITool,
		scanners.KindAgentSkill,
	}
	return run(ctx, opts)
}

// scanRunner is the function shape captured by the cobra RunE closure;
// extracted so tests can replace it without executing the full pipeline.
type scanRunner func(ctx context.Context, opts Options) error

// scanDeps groups the injectable builders runScanWithDeps depends on.
// Tests inject stubs; production wires the real builders via runScan.
type scanDeps struct {
	resolver       auth.Resolver
	buildScanners  func(opts Options) ([]inventory.Scanner, error)
	buildLocalSink func(opts Options) inventory.Sink
	// buildCloudSink returns the cloud sink, an optional cleanup hook
	// (closes the underlying gRPC conn), and an error. The hook runs
	// after the orchestrator returns so the conn outlives Sync's drain
	// on Close.
	buildCloudSink func(ctx context.Context, creds auth.Credentials, opts Options) (inventory.Sink, func(), error)
}

// newScanCommand returns the production `vet endpoint scan` cobra
// command, wired against the production scanRunner (runScan).
func newScanCommand() *cobra.Command {
	return newScanCommandWithRunner(runScan)
}

// newScanCommandWithRunner constructs a scan command whose RunE invokes
// the supplied runner. Tests inject a runner that records the parsed
// options instead of executing a real scan.
func newScanCommandWithRunner(run scanRunner) *cobra.Command {
	opts := &Options{
		DrainTimeout: DefaultDrainTimeout,
	}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan the endpoint and (when credentials are configured) sync results to SafeDep Cloud",
		Long: `Scan this endpoint for installed inventory (AI tools, MCP servers, coding
agents, AI extensions). When SafeDep credentials are configured the discovered
items are streamed to SafeDep Cloud; without credentials the command prints a
local table and exits 0 with a hint.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), *opts)
		},
	}

	cmd.Flags().StringArrayVar(&opts.Scopes, "scope", nil,
		"Limit to specific scopes (system, project); repeatable, empty for all")
	cmd.Flags().StringVarP(&opts.ProjectDir, "project-dir", "D", "",
		"Project root for project-level discovery (default: cwd)")
	cmd.Flags().StringVar(&opts.ReportJSON, "report-json", "",
		"Write JSON inventory to file")
	cmd.Flags().BoolVarP(&opts.Silent, "silent", "s", false,
		"Suppress default summary output")
	cmd.Flags().StringArrayVar(&opts.Kinds, "kind", nil,
		fmt.Sprintf("Limit to specific scanner kinds (allowed: %s); repeatable, empty for all", strings.Join(scanners.AllowedKinds(), ", ")))
	cmd.Flags().DurationVar(&opts.DrainTimeout, "drain-timeout", DefaultDrainTimeout,
		"Maximum time to wait for pending cloud uploads to finish on exit")

	return cmd
}

func runScan(ctx context.Context, opts Options) error {
	deps := scanDeps{
		resolver: auth.NewLayeredResolver(),
		buildScanners: func(opts Options) ([]inventory.Scanner, error) {
			return scanners.Build(opts.Kinds)
		},
		buildLocalSink: buildLocalSink,
		buildCloudSink: buildCloudSink,
	}
	return runScanWithDeps(ctx, opts, deps)
}

// runScanWithDeps is the testable core. The resolver outcome dictates
// whether a CloudSink is added; on any non-success the local sink path
// runs alone. The CloudSink is only built when the resolver returns
// success, so users without credentials never open the WAL.
func runScanWithDeps(ctx context.Context, opts Options, deps scanDeps) error {
	cfg, err := buildScanConfig(opts)
	if err != nil {
		return err
	}

	scannerSet, err := deps.buildScanners(opts)
	if err != nil {
		return err
	}

	sinks := []inventory.Sink{deps.buildLocalSink(opts)}

	cloudCleanup := func() {}
	creds, resolveErr := deps.resolver.Resolve(ctx)
	switch {
	case resolveErr == nil:
		cloudSink, cleanup, err := deps.buildCloudSink(ctx, creds, opts)
		if err != nil {
			ui.PrintWarning("vet endpoint scan: failed to enable cloud sync (%v); continuing with local-only output", err)
			break
		}
		if cleanup != nil {
			cloudCleanup = cleanup
		}
		sinks = append(sinks, cloudSink)
	case errors.Is(resolveErr, auth.ErrNoCredentials):
		ui.PrintMsg("SafeDep cloud sync available; run `vet auth configure` or set SAFEDEP_API_KEY and SAFEDEP_TENANT_ID to enable.")
	case errors.Is(resolveErr, auth.ErrIncompleteCredentials):
		ui.PrintWarning("vet endpoint scan: %v; continuing with local-only output", resolveErr)
	default:
		ui.PrintWarning("vet endpoint scan: credential resolution failed (%v); continuing with local-only output", resolveErr)
	}
	defer cloudCleanup()

	return inventory.New(scannerSet, sinks).Run(ctx, cfg)
}

// buildScanConfig translates Options into the read-only ScanConfig the
// inventory orchestrator hands to scanners. ProjectDir defaults to the
// current working directory when no override is supplied so
// project-scoped scanners always have a root to walk.
func buildScanConfig(opts Options) (inventory.ScanConfig, error) {
	projectDir := opts.ProjectDir
	if projectDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return inventory.ScanConfig{}, fmt.Errorf("vet endpoint scan: resolve project dir: %w", err)
		}
		projectDir = cwd
	}

	scopes, err := parseScopes(opts.Scopes)
	if err != nil {
		return inventory.ScanConfig{}, err
	}
	return inventory.ScanConfig{
		ProjectDir: projectDir,
		Scopes:     scopes,
	}, nil
}

// parseScopes converts CLI --scope strings to inventory.Scope values.
// nil input preserves the orchestrator's "all scopes enabled" semantics
// (matches aitool.DiscoveryConfig). An unknown value is rejected with a
// clear error so a typo doesn't silently disable a scope.
func parseScopes(scopes []string) ([]inventory.Scope, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	out := make([]inventory.Scope, 0, len(scopes))
	for _, s := range scopes {
		switch s {
		case "system":
			out = append(out, inventory.ScopeSystem)
		case "project":
			out = append(out, inventory.ScopeProject)
		default:
			return nil, fmt.Errorf("vet endpoint scan: unsupported --scope value %q (allowed: system, project)", s)
		}
	}
	return out, nil
}

// buildLocalSink composes the production LocalSink from the user-facing
// flags. WithOutput is left at its default (os.Stderr) so the table
// renders to the same stream `vet ai discover` has used historically.
func buildLocalSink(opts Options) inventory.Sink {
	sinkOpts := []localsink.Option{}
	if opts.Silent {
		sinkOpts = append(sinkOpts, localsink.WithSilent())
	}
	if opts.ReportJSON != "" {
		sinkOpts = append(sinkOpts, localsink.WithReportJSON(opts.ReportJSON))
	}
	return localsink.New(sinkOpts...)
}

// buildCloudSink dials the SafeDep sync endpoint, constructs the
// endpointsync client, and wraps it in a CloudSink. The WAL persists
// across runs at the endpointsync default path; delivered events are
// purged on every successful Sync, undelivered events are bounded by
// endpointsync's 100k pending cap. The cleanup hook closes the gRPC
// conn (endpointsync's transport Close is a no-op).
func buildCloudSink(_ context.Context, creds auth.Credentials, opts Options) (inventory.Sink, func(), error) {
	conn, err := dialSyncConn(creds)
	if err != nil {
		return nil, nil, fmt.Errorf("dial sync endpoint: %w", err)
	}

	client, err := endpointsync.NewSyncClient(
		"vet",
		toolVersion(),
		endpointsync.NewGrpcTransport(conn),
		endpointsync.NewEndpointIdentityResolver(),
	)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("init endpointsync client: %w", err)
	}

	sink := cloudsink.New(client, cloudsink.WithDrainTimeout(opts.DrainTimeout))
	cleanup := func() { _ = conn.Close() }
	return sink, cleanup, nil
}

// dialSyncConn opens a gRPC connection to the SafeDep sync endpoint
// using the supplied Credentials directly, so resolver outputs that
// were not written to the auth package globals still authenticate
// correctly.
func dialSyncConn(creds auth.Credentials) (*grpc.ClientConn, error) {
	parsed, err := url.Parse(auth.SyncApiUrl())
	if err != nil {
		return nil, fmt.Errorf("parse sync api url: %w", err)
	}
	host, port := parsed.Hostname(), parsed.Port()
	if port == "" {
		port = "443"
	}

	headers := http.Header{}
	headers.Set("x-tenant-id", creds.TenantID)
	if mockUser := os.Getenv("VET_CONTROL_TOWER_MOCK_USER"); mockUser != "" {
		headers.Set("x-mock-user", mockUser)
	}

	conn, err := drygrpc.GrpcClient("vet-endpointsync", host, port, creds.APIKey, headers, []grpc.DialOption{})
	if err != nil {
		return nil, fmt.Errorf("grpc dial: %w", err)
	}
	return conn, nil
}

// toolVersion returns the build-stamped version, falling back to "dev"
// for unversioned local builds since endpointsync requires non-empty.
func toolVersion() string {
	v := command.GetVersion()
	if v == "" {
		return "dev"
	}
	return v
}
