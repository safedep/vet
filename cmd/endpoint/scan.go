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
	"io"
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
	"github.com/safedep/vet/pkg/inventory"
	"github.com/safedep/vet/pkg/inventory/scanners"
	cloudsink "github.com/safedep/vet/pkg/inventory/sinks/cloud"
	localsink "github.com/safedep/vet/pkg/inventory/sinks/local"
)

// DefaultDrainTimeout is the default `--drain-timeout` value and the
// fallback when AliasOptions.DrainTimeout is zero. Mirrors the cloud
// sink's own default.
const DefaultDrainTimeout = 30 * time.Second

// scanOptions is the parsed form of the `vet endpoint scan` flag set.
// Exported field names would belong on a public surface; this struct is
// intentionally package-private so the alias in cmd/ai stays the only
// other caller.
type scanOptions struct {
	scopes       []string
	projectDir   string
	reportJSON   string
	silent       bool
	kinds        []string
	drainTimeout time.Duration
}

// AliasOptions is the public surface for cmd packages that re-export
// `vet endpoint scan` under a friendlier name. It excludes --kind on
// purpose: an alias pins the scanner kind via its dedicated entrypoint
// (e.g. RunAITool), it does not pick the kind set itself.
type AliasOptions struct {
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
	// DrainTimeout bounds CloudSink.Close's wait for the WAL to ship.
	// Zero falls back to DefaultDrainTimeout.
	DrainTimeout time.Duration
}

// RunAITool runs the endpoint-scan pipeline pinned to the ai-tool kind.
// It is the integration point for cmd/ai/discover.
func RunAITool(ctx context.Context, opts AliasOptions) error {
	return runAlias(ctx, opts, []string{scanners.KindAITool})
}

func runAlias(ctx context.Context, opts AliasOptions, kinds []string) error {
	drain := opts.DrainTimeout
	if drain <= 0 {
		drain = DefaultDrainTimeout
	}
	return runScan(ctx, scanOptions{
		scopes:       opts.Scopes,
		projectDir:   opts.ProjectDir,
		reportJSON:   opts.ReportJSON,
		silent:       opts.Silent,
		kinds:        kinds,
		drainTimeout: drain,
	})
}

// scanRunner is the function shape captured by the cobra RunE closure;
// extracted so tests can replace it without executing the full pipeline.
type scanRunner func(ctx context.Context, opts scanOptions) error

// scanDeps groups the injectable builders runScanWithDeps depends on.
// Tests inject stubs; production wires the real builders via runScan.
type scanDeps struct {
	resolver       auth.Resolver
	buildScanners  func(opts scanOptions) ([]inventory.Scanner, error)
	buildLocalSink func(opts scanOptions) inventory.Sink
	// buildCloudSink returns the cloud sink, an optional cleanup hook
	// (closes the underlying gRPC conn), and an error. The cleanup hook
	// runs after the orchestrator returns so the conn outlives Sync's
	// drain on Close.
	buildCloudSink func(ctx context.Context, creds auth.Credentials, opts scanOptions) (inventory.Sink, func(), error)
	stderr         io.Writer
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
	opts := &scanOptions{
		drainTimeout: DefaultDrainTimeout,
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

	cmd.Flags().StringArrayVar(&opts.scopes, "scope", nil,
		"Limit to specific scopes (system, project); repeatable, empty for all")
	cmd.Flags().StringVarP(&opts.projectDir, "project-dir", "D", "",
		"Project root for project-level discovery (default: cwd)")
	cmd.Flags().StringVar(&opts.reportJSON, "report-json", "",
		"Write JSON inventory to file")
	cmd.Flags().BoolVarP(&opts.silent, "silent", "s", false,
		"Suppress default summary output")
	cmd.Flags().StringArrayVar(&opts.kinds, "kind", nil,
		fmt.Sprintf("Limit to specific scanner kinds (allowed: %s); repeatable, empty for all", strings.Join(scanners.AllowedKinds(), ", ")))
	cmd.Flags().DurationVar(&opts.drainTimeout, "drain-timeout", DefaultDrainTimeout,
		"Maximum time to wait for pending cloud uploads to finish on exit")

	return cmd
}

func runScan(ctx context.Context, opts scanOptions) error {
	deps := scanDeps{
		resolver: auth.NewLayeredResolver(),
		buildScanners: func(opts scanOptions) ([]inventory.Scanner, error) {
			return scanners.Build(opts.kinds)
		},
		buildLocalSink: buildLocalSink,
		buildCloudSink: buildCloudSink,
		stderr:         os.Stderr,
	}
	return runScanWithDeps(ctx, opts, deps)
}

// runScanWithDeps is the testable core. The resolver outcome dictates
// whether a CloudSink is added; on any non-success the local sink path
// runs alone and the user keeps the table.
func runScanWithDeps(ctx context.Context, opts scanOptions, deps scanDeps) error {
	stderr := deps.stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	cfg, err := buildScanConfig(opts)
	if err != nil {
		return err
	}

	scanners, err := deps.buildScanners(opts)
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
			_, _ = fmt.Fprintf(stderr, "vet endpoint scan: failed to enable cloud sync (%v); continuing with local-only output\n", err)
			break
		}
		if cleanup != nil {
			cloudCleanup = cleanup
		}
		sinks = append(sinks, cloudSink)
	case errors.Is(resolveErr, auth.ErrNoCredentials):
		_, _ = fmt.Fprintln(stderr, "SafeDep cloud sync available; run `vet auth configure` or set SAFEDEP_API_KEY and SAFEDEP_TENANT_ID to enable.")
	case errors.Is(resolveErr, auth.ErrIncompleteCredentials):
		_, _ = fmt.Fprintf(stderr, "vet endpoint scan: %v; continuing with local-only output\n", resolveErr)
	default:
		_, _ = fmt.Fprintf(stderr, "vet endpoint scan: credential resolution failed (%v); continuing with local-only output\n", resolveErr)
	}
	defer cloudCleanup()

	return inventory.New(scanners, sinks).Run(ctx, cfg)
}

// buildScanConfig translates scanOptions into the read-only ScanConfig
// the inventory orchestrator hands to scanners. ProjectDir defaults to
// the current working directory when no override is supplied so
// project-scoped scanners always have a root to walk.
func buildScanConfig(opts scanOptions) (inventory.ScanConfig, error) {
	projectDir := opts.projectDir
	if projectDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return inventory.ScanConfig{}, fmt.Errorf("vet endpoint scan: resolve project dir: %w", err)
		}
		projectDir = cwd
	}

	scopes, err := parseScopes(opts.scopes)
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
func buildLocalSink(opts scanOptions) inventory.Sink {
	sinkOpts := []localsink.Option{}
	if opts.silent {
		sinkOpts = append(sinkOpts, localsink.WithSilent())
	}
	if opts.reportJSON != "" {
		sinkOpts = append(sinkOpts, localsink.WithReportJSON(opts.reportJSON))
	}
	return localsink.New(sinkOpts...)
}

// buildCloudSink dials the SafeDep sync endpoint, constructs the
// endpointsync client, and wraps it in a CloudSink. The returned
// cleanup closes the gRPC conn after the orchestrator's drain;
// endpointsync's transport Close is a no-op so the conn is owned here.
func buildCloudSink(_ context.Context, creds auth.Credentials, opts scanOptions) (inventory.Sink, func(), error) {
	conn, err := dialSyncConn(creds)
	if err != nil {
		return nil, nil, fmt.Errorf("dial sync endpoint: %w", err)
	}

	transport := endpointsync.NewGrpcTransport(conn)
	identity := endpointsync.NewEndpointIdentityResolver()

	client, err := endpointsync.NewSyncClient(
		"vet",
		toolVersion(),
		transport,
		identity,
	)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("init endpointsync client: %w", err)
	}

	sink := cloudsink.New(client, cloudsink.WithDrainTimeout(opts.drainTimeout))
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
