package endpoint

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/pkg/inventory"
	"github.com/safedep/vet/pkg/inventory/scanners"
)

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
// Options for every documented flag. The command's RunE is replaced
// with a closure that records the parsed options instead of running.
func TestScanCommand_FlagParsing(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		opts := captureScanOptions(t, []string{})
		assert.Empty(t, opts.Scopes)
		assert.Empty(t, opts.ProjectDir)
		assert.Empty(t, opts.ReportJSON)
		assert.False(t, opts.Silent)
		assert.Empty(t, opts.Kinds)
		assert.Equal(t, 30*time.Second, opts.DrainTimeout)
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
		assert.Equal(t, []string{"system", "project"}, opts.Scopes)
		assert.Equal(t, "/tmp/proj", opts.ProjectDir)
		assert.Equal(t, "/tmp/out.json", opts.ReportJSON)
		assert.True(t, opts.Silent)
		assert.Equal(t, []string{"ai-tool"}, opts.Kinds)
		assert.Equal(t, 5*time.Second, opts.DrainTimeout)
	})

	t.Run("short flags", func(t *testing.T) {
		opts := captureScanOptions(t, []string{
			"-D", "/tmp/p",
			"-s",
		})
		assert.Equal(t, "/tmp/p", opts.ProjectDir)
		assert.True(t, opts.Silent)
	})
}

// captureScanOptions builds a fresh scan command, swaps RunE to record the
// resolved options, executes with args, and returns the captured options.
func captureScanOptions(t *testing.T, args []string) Options {
	t.Helper()
	var captured Options
	captureRun := func(_ context.Context, opts Options) error {
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

// TestRunAITool_DoesNotIncludeIDEExtensionKind ensures that RunAITool (the
// entry point for `vet ai discover`) does not pin ide-extension in its kind
// set. IDE extensions belong to endpoint scan only.
func TestRunAITool_DoesNotIncludeIDEExtensionKind(t *testing.T) {
	var capturedKinds []string
	_ = runAIToolWithRunner(context.Background(), Options{}, func(_ context.Context, opts Options) error {
		capturedKinds = opts.Kinds
		return nil
	})

	assert.NotContains(t, capturedKinds, scanners.KindIDEExtension,
		"ide-extension must not run under vet ai discover")
}

func TestRunScanWithDeps_NoCredentials_BuildsLocalSinkOnly(t *testing.T) {
	resolver := stubResolver{err: auth.ErrNoCredentials}
	local := &recordingSink{}
	cloudCalled := false

	deps := scanDeps{
		resolver: resolver,
		buildScanners: func(_ Options) ([]inventory.Scanner, error) {
			return []inventory.Scanner{&fakeScanner{items: itemsForTest()}}, nil
		},
		buildLocalSink: func(_ Options) inventory.Sink { return local },
		buildCloudSink: func(_ context.Context, _ auth.Credentials, _ Options) (inventory.Sink, func(), error) {
			cloudCalled = true
			return nil, nil, nil
		},
	}
	err := runScanWithDeps(context.Background(), Options{DrainTimeout: time.Second}, deps)
	require.NoError(t, err)

	assert.False(t, cloudCalled, "buildCloudSink must not be called when credentials are absent")
	assert.Equal(t, 1, local.beginCalls)
	assert.Len(t, local.emitItems, len(itemsForTest()))
	assert.Equal(t, 1, local.endCalls)
	assert.Equal(t, 1, local.closeCalls)
}

func TestRunScanWithDeps_CredentialsPresent_BuildsCloudSink(t *testing.T) {
	resolver := stubResolver{creds: auth.Credentials{APIKey: "k", TenantID: "t"}}
	local := &recordingSink{}
	cloud := &recordingSink{}
	closerCalled := false

	deps := scanDeps{
		resolver: resolver,
		buildScanners: func(_ Options) ([]inventory.Scanner, error) {
			return []inventory.Scanner{&fakeScanner{items: itemsForTest()}}, nil
		},
		buildLocalSink: func(_ Options) inventory.Sink { return local },
		buildCloudSink: func(_ context.Context, creds auth.Credentials, _ Options) (inventory.Sink, func(), error) {
			assert.Equal(t, "k", creds.APIKey)
			assert.Equal(t, "t", creds.TenantID)
			return cloud, func() { closerCalled = true }, nil
		},
	}

	err := runScanWithDeps(context.Background(), Options{DrainTimeout: time.Second}, deps)
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
		buildScanners: func(_ Options) ([]inventory.Scanner, error) {
			return []inventory.Scanner{&fakeScanner{items: itemsForTest()}}, nil
		},
		buildLocalSink: func(_ Options) inventory.Sink { return local },
		buildCloudSink: func(_ context.Context, _ auth.Credentials, _ Options) (inventory.Sink, func(), error) {
			return nil, nil, errors.New("boom")
		},
	}
	err := runScanWithDeps(context.Background(), Options{DrainTimeout: time.Second}, deps)
	require.NoError(t, err)

	assert.Equal(t, 1, local.beginCalls)
	assert.Equal(t, 1, local.endCalls)
	assert.Equal(t, 1, local.closeCalls)
}

func TestRunScanWithDeps_IncompleteCredentials_ContinuesWithLocalOnly(t *testing.T) {
	resolver := stubResolver{
		err: fmt.Errorf("%w: API key set but tenant missing", auth.ErrIncompleteCredentials),
	}
	local := &recordingSink{}
	cloudCalled := false

	deps := scanDeps{
		resolver: resolver,
		buildScanners: func(_ Options) ([]inventory.Scanner, error) {
			return []inventory.Scanner{&fakeScanner{items: nil}}, nil
		},
		buildLocalSink: func(_ Options) inventory.Sink { return local },
		buildCloudSink: func(_ context.Context, _ auth.Credentials, _ Options) (inventory.Sink, func(), error) {
			cloudCalled = true
			return nil, nil, nil
		},
	}
	err := runScanWithDeps(context.Background(), Options{DrainTimeout: time.Second}, deps)
	require.NoError(t, err)

	assert.False(t, cloudCalled, "buildCloudSink must not be called when credentials are partial")
	assert.Equal(t, 1, local.beginCalls)
	assert.Equal(t, 1, local.endCalls)
	assert.Equal(t, 1, local.closeCalls)
}

func TestRunScanWithDeps_ResolverGenericError_ContinuesWithLocalOnly(t *testing.T) {
	resolver := stubResolver{err: errors.New("keychain explode")}
	local := &recordingSink{}
	cloudCalled := false

	deps := scanDeps{
		resolver: resolver,
		buildScanners: func(_ Options) ([]inventory.Scanner, error) {
			return []inventory.Scanner{&fakeScanner{items: nil}}, nil
		},
		buildLocalSink: func(_ Options) inventory.Sink { return local },
		buildCloudSink: func(_ context.Context, _ auth.Credentials, _ Options) (inventory.Sink, func(), error) {
			cloudCalled = true
			return nil, nil, nil
		},
	}
	err := runScanWithDeps(context.Background(), Options{DrainTimeout: time.Second}, deps)
	require.NoError(t, err)

	assert.False(t, cloudCalled)
	assert.Equal(t, 1, local.beginCalls)
}

func TestRunScanWithDeps_ProjectDirDefaultsToCwd(t *testing.T) {
	var capturedCfg inventory.ScanConfig
	deps := scanDeps{
		resolver: stubResolver{err: auth.ErrNoCredentials},
		buildScanners: func(opts Options) ([]inventory.Scanner, error) {
			return []inventory.Scanner{capturingScanner(&capturedCfg)}, nil
		},
		buildLocalSink: func(_ Options) inventory.Sink { return &recordingSink{} },
		buildCloudSink: func(_ context.Context, _ auth.Credentials, _ Options) (inventory.Sink, func(), error) {
			return nil, nil, nil
		},
	}
	err := runScanWithDeps(context.Background(), Options{DrainTimeout: time.Second}, deps)
	require.NoError(t, err)
	assert.NotEmpty(t, capturedCfg.ProjectDir, "ProjectDir should default to cwd when flag is empty")
}

func TestRunScanWithDeps_ScopeFlagPropagatesToScanConfig(t *testing.T) {
	var capturedCfg inventory.ScanConfig
	deps := scanDeps{
		resolver: stubResolver{err: auth.ErrNoCredentials},
		buildScanners: func(_ Options) ([]inventory.Scanner, error) {
			return []inventory.Scanner{capturingScanner(&capturedCfg)}, nil
		},
		buildLocalSink: func(_ Options) inventory.Sink { return &recordingSink{} },
		buildCloudSink: func(_ context.Context, _ auth.Credentials, _ Options) (inventory.Sink, func(), error) {
			return nil, nil, nil
		},
	}
	opts := Options{
		Scopes:       []string{"system", "project"},
		ProjectDir:   "/tmp/proj",
		DrainTimeout: time.Second,
	}
	err := runScanWithDeps(context.Background(), opts, deps)
	require.NoError(t, err)
	assert.Equal(t, "/tmp/proj", capturedCfg.ProjectDir)
	assert.ElementsMatch(t, []inventory.Scope{inventory.ScopeSystem, inventory.ScopeProject}, capturedCfg.Scopes)
}

func TestRunScanWithDeps_BuildScannersError_Aborts(t *testing.T) {
	deps := scanDeps{
		resolver: stubResolver{err: auth.ErrNoCredentials},
		buildScanners: func(_ Options) ([]inventory.Scanner, error) {
			return nil, errors.New("unknown kind: foo")
		},
		buildLocalSink: func(_ Options) inventory.Sink { return &recordingSink{} },
		buildCloudSink: func(_ context.Context, _ auth.Credentials, _ Options) (inventory.Sink, func(), error) {
			return nil, nil, nil
		},
	}
	err := runScanWithDeps(context.Background(), Options{DrainTimeout: time.Second}, deps)
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
