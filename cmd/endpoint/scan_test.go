package endpoint

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/pkg/inventory"
)

// depsWithStderr clones deps with the supplied writer attached so a
// test can capture the user-facing hint output.
func depsWithStderr(d scanDeps, w *bytes.Buffer) scanDeps {
	d.stderr = w
	return d
}

// stubResolver implements auth.Resolver for tests.
type stubResolver struct {
	creds auth.Credentials
	err   error
}

func (s stubResolver) Resolve(_ context.Context) (auth.Credentials, error) {
	return s.creds, s.err
}

// fakeScanner is an inventory.Scanner that emits a fixed list of items so
// tests can verify Run fan-out without touching the filesystem.
type fakeScanner struct {
	items []*inventory.Item
}

func (f *fakeScanner) Name() string { return "fake" }

func (f *fakeScanner) Scan(_ context.Context, _ inventory.ScanConfig, emit inventory.EmitFunc) error {
	for _, it := range f.items {
		if err := emit(it); err != nil {
			return err
		}
	}
	return nil
}

// recordingSink captures the lifecycle calls observed by a sink so tests can
// verify the orchestrator received the expected configuration.
type recordingSink struct {
	beginCalls int
	emitItems  []*inventory.Item
	endCalls   int
	closeCalls int
	session    *inventory.Session
}

func (s *recordingSink) Begin(_ context.Context, session *inventory.Session) error {
	s.beginCalls++
	s.session = session
	return nil
}

func (s *recordingSink) Emit(_ context.Context, item *inventory.Item) error {
	s.emitItems = append(s.emitItems, item)
	return nil
}

func (s *recordingSink) End(_ context.Context, _ *inventory.ScanSummary) error {
	s.endCalls++
	return nil
}

func (s *recordingSink) Close(_ context.Context) error {
	s.closeCalls++
	return nil
}

// TestScanCommand_FlagParsing verifies that cobra wiring populates
// scanOptions for every documented flag. The command's RunE is replaced
// with a closure that records the parsed options instead of running.
func TestScanCommand_FlagParsing(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		opts := captureScanOptions(t, []string{})
		assert.Empty(t, opts.scopes)
		assert.Empty(t, opts.projectDir)
		assert.Empty(t, opts.reportJSON)
		assert.False(t, opts.silent)
		assert.Empty(t, opts.kinds)
		assert.Equal(t, 30*time.Second, opts.drainTimeout)
	})

	t.Run("all flags", func(t *testing.T) {
		opts := captureScanOptions(t, []string{
			"--scope", "system",
			"--scope", "project",
			"--project-dir", "/tmp/proj",
			"--report-json", "/tmp/out.json",
			"--silent",
			"--kind", "ai-tool",
			"--drain-timeout", "5s",
		})
		assert.Equal(t, []string{"system", "project"}, opts.scopes)
		assert.Equal(t, "/tmp/proj", opts.projectDir)
		assert.Equal(t, "/tmp/out.json", opts.reportJSON)
		assert.True(t, opts.silent)
		assert.Equal(t, []string{"ai-tool"}, opts.kinds)
		assert.Equal(t, 5*time.Second, opts.drainTimeout)
	})

	t.Run("short flags", func(t *testing.T) {
		opts := captureScanOptions(t, []string{
			"-D", "/tmp/p",
			"-s",
		})
		assert.Equal(t, "/tmp/p", opts.projectDir)
		assert.True(t, opts.silent)
	})
}

// captureScanOptions builds a fresh scan command, swaps RunE to record the
// resolved options, executes with args, and returns the captured options.
func captureScanOptions(t *testing.T, args []string) scanOptions {
	t.Helper()
	var captured scanOptions
	captureRun := func(_ context.Context, opts scanOptions) error {
		captured = opts
		return nil
	}
	cmd := newScanCommandWithRunner(captureRun)
	cmd.SetArgs(args)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	require.NoError(t, cmd.Execute())
	return captured
}

func TestRunScanWithDeps_NoCredentials_BuildsLocalSinkOnly(t *testing.T) {
	resolver := stubResolver{err: auth.ErrNoCredentials}
	local := &recordingSink{}
	cloudCalled := false

	deps := scanDeps{
		resolver: resolver,
		buildScanners: func(_ scanOptions) ([]inventory.Scanner, error) {
			return []inventory.Scanner{&fakeScanner{items: itemsForTest()}}, nil
		},
		buildLocalSink: func(_ scanOptions) inventory.Sink { return local },
		buildCloudSink: func(_ context.Context, _ auth.Credentials, _ scanOptions) (inventory.Sink, func(), error) {
			cloudCalled = true
			return nil, nil, nil
		},
	}
	stderr := &bytes.Buffer{}

	err := runScanWithDeps(context.Background(), scanOptions{drainTimeout: time.Second}, depsWithStderr(deps, stderr))
	require.NoError(t, err)

	assert.False(t, cloudCalled, "buildCloudSink must not be called when credentials are absent")
	assert.Equal(t, 1, local.beginCalls)
	assert.Len(t, local.emitItems, len(itemsForTest()))
	assert.Equal(t, 1, local.endCalls)
	assert.Equal(t, 1, local.closeCalls)
	assert.Contains(t, stderr.String(), "SafeDep")
	assert.Contains(t, stderr.String(), "vet auth configure")
	assert.Contains(t, stderr.String(), "SAFEDEP_API_KEY")
	assert.Contains(t, stderr.String(), "SAFEDEP_TENANT_ID")
}

func TestRunScanWithDeps_CredentialsPresent_BuildsCloudSink(t *testing.T) {
	resolver := stubResolver{creds: auth.Credentials{APIKey: "k", TenantID: "t"}}
	local := &recordingSink{}
	cloud := &recordingSink{}
	closerCalled := false

	deps := scanDeps{
		resolver: resolver,
		buildScanners: func(_ scanOptions) ([]inventory.Scanner, error) {
			return []inventory.Scanner{&fakeScanner{items: itemsForTest()}}, nil
		},
		buildLocalSink: func(_ scanOptions) inventory.Sink { return local },
		buildCloudSink: func(_ context.Context, creds auth.Credentials, _ scanOptions) (inventory.Sink, func(), error) {
			assert.Equal(t, "k", creds.APIKey)
			assert.Equal(t, "t", creds.TenantID)
			return cloud, func() { closerCalled = true }, nil
		},
	}

	err := runScanWithDeps(context.Background(), scanOptions{drainTimeout: time.Second}, deps)
	require.NoError(t, err)

	assert.Equal(t, 1, local.beginCalls)
	assert.Equal(t, 1, cloud.beginCalls)
	assert.Len(t, cloud.emitItems, len(itemsForTest()))
	assert.True(t, closerCalled, "cloud closer must be invoked at end of scan")
}

func TestRunScanWithDeps_CloudConstructionError_ContinuesWithLocalOnly(t *testing.T) {
	resolver := stubResolver{creds: auth.Credentials{APIKey: "k", TenantID: "t"}}
	local := &recordingSink{}

	deps := scanDeps{
		resolver: resolver,
		buildScanners: func(_ scanOptions) ([]inventory.Scanner, error) {
			return []inventory.Scanner{&fakeScanner{items: itemsForTest()}}, nil
		},
		buildLocalSink: func(_ scanOptions) inventory.Sink { return local },
		buildCloudSink: func(_ context.Context, _ auth.Credentials, _ scanOptions) (inventory.Sink, func(), error) {
			return nil, nil, errors.New("boom")
		},
	}
	stderr := &bytes.Buffer{}

	err := runScanWithDeps(context.Background(), scanOptions{drainTimeout: time.Second}, depsWithStderr(deps, stderr))
	require.NoError(t, err)

	assert.Equal(t, 1, local.beginCalls)
	assert.Equal(t, 1, local.endCalls)
	assert.Equal(t, 1, local.closeCalls)
	assert.Contains(t, stderr.String(), "boom", "construction error should be reported on stderr")
}

func TestRunScanWithDeps_ResolverGenericError_ContinuesWithLocalOnly(t *testing.T) {
	resolver := stubResolver{err: errors.New("keychain explode")}
	local := &recordingSink{}
	cloudCalled := false

	deps := scanDeps{
		resolver: resolver,
		buildScanners: func(_ scanOptions) ([]inventory.Scanner, error) {
			return []inventory.Scanner{&fakeScanner{items: nil}}, nil
		},
		buildLocalSink: func(_ scanOptions) inventory.Sink { return local },
		buildCloudSink: func(_ context.Context, _ auth.Credentials, _ scanOptions) (inventory.Sink, func(), error) {
			cloudCalled = true
			return nil, nil, nil
		},
	}
	stderr := &bytes.Buffer{}

	err := runScanWithDeps(context.Background(), scanOptions{drainTimeout: time.Second}, depsWithStderr(deps, stderr))
	require.NoError(t, err)

	assert.False(t, cloudCalled)
	assert.Equal(t, 1, local.beginCalls)
	assert.Contains(t, stderr.String(), "keychain explode")
}

func TestRunScanWithDeps_ProjectDirDefaultsToCwd(t *testing.T) {
	var capturedCfg inventory.ScanConfig
	deps := scanDeps{
		resolver: stubResolver{err: auth.ErrNoCredentials},
		buildScanners: func(opts scanOptions) ([]inventory.Scanner, error) {
			return []inventory.Scanner{capturingScanner(&capturedCfg)}, nil
		},
		buildLocalSink: func(_ scanOptions) inventory.Sink { return &recordingSink{} },
		buildCloudSink: func(_ context.Context, _ auth.Credentials, _ scanOptions) (inventory.Sink, func(), error) {
			return nil, nil, nil
		},
	}
	err := runScanWithDeps(context.Background(), scanOptions{drainTimeout: time.Second}, deps)
	require.NoError(t, err)
	assert.NotEmpty(t, capturedCfg.ProjectDir, "ProjectDir should default to cwd when flag is empty")
}

func TestRunScanWithDeps_ScopeFlagPropagatesToScanConfig(t *testing.T) {
	var capturedCfg inventory.ScanConfig
	deps := scanDeps{
		resolver: stubResolver{err: auth.ErrNoCredentials},
		buildScanners: func(_ scanOptions) ([]inventory.Scanner, error) {
			return []inventory.Scanner{capturingScanner(&capturedCfg)}, nil
		},
		buildLocalSink: func(_ scanOptions) inventory.Sink { return &recordingSink{} },
		buildCloudSink: func(_ context.Context, _ auth.Credentials, _ scanOptions) (inventory.Sink, func(), error) {
			return nil, nil, nil
		},
	}
	opts := scanOptions{
		scopes:       []string{"system", "project"},
		projectDir:   "/tmp/proj",
		drainTimeout: time.Second,
	}
	err := runScanWithDeps(context.Background(), opts, deps)
	require.NoError(t, err)
	assert.Equal(t, "/tmp/proj", capturedCfg.ProjectDir)
	assert.ElementsMatch(t, []inventory.Scope{inventory.ScopeSystem, inventory.ScopeProject}, capturedCfg.Scopes)
}

func TestRunScanWithDeps_BuildScannersError_Aborts(t *testing.T) {
	deps := scanDeps{
		resolver: stubResolver{err: auth.ErrNoCredentials},
		buildScanners: func(_ scanOptions) ([]inventory.Scanner, error) {
			return nil, errors.New("unknown kind: foo")
		},
		buildLocalSink: func(_ scanOptions) inventory.Sink { return &recordingSink{} },
		buildCloudSink: func(_ context.Context, _ auth.Credentials, _ scanOptions) (inventory.Sink, func(), error) {
			return nil, nil, nil
		},
	}
	err := runScanWithDeps(context.Background(), scanOptions{drainTimeout: time.Second}, deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown kind")
}

// Scanner-build coverage lives in pkg/inventory/scanners; this file
// only exercises the cmd-layer wiring around it.

func TestParseScopes(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		got, err := parseScopes(nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})
	t.Run("system+project", func(t *testing.T) {
		got, err := parseScopes([]string{"system", "project"})
		require.NoError(t, err)
		assert.Equal(t, []inventory.Scope{inventory.ScopeSystem, inventory.ScopeProject}, got)
	})
	t.Run("unknown rejected", func(t *testing.T) {
		_, err := parseScopes([]string{"weird"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "weird")
	})
}

// itemsForTest returns a small fixed slice of inventory items used to verify
// fan-out across sinks.
func itemsForTest() []*inventory.Item {
	return []*inventory.Item{
		{Kind: inventory.KindMCPServer, Name: "alpha"},
		{Kind: inventory.KindCodingAgent, Name: "beta"},
	}
}

// capturingScanner returns a Scanner that copies its received ScanConfig
// into the supplied pointer. Used to verify the orchestrator hands the
// expected config to scanners.
func capturingScanner(out *inventory.ScanConfig) inventory.Scanner {
	return &configCapturingScanner{out: out}
}

type configCapturingScanner struct{ out *inventory.ScanConfig }

func (s *configCapturingScanner) Name() string { return "capture" }

func (s *configCapturingScanner) Scan(_ context.Context, cfg inventory.ScanConfig, _ inventory.EmitFunc) error {
	*s.out = cfg
	return nil
}
