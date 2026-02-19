package aitool

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

const cliProbeTimeout = 5 * time.Second

// CLIToolVerifier is implemented by each AI CLI tool plugin.
type CLIToolVerifier interface {
	// BinaryNames returns candidate binary names to search in PATH.
	BinaryNames() []string

	// VerifyArgs returns the arguments to execute for identity verification.
	VerifyArgs() []string

	// VerifyOutput checks the command output and confirms this is the expected tool.
	// Returns (version string, true) if verified, ("", false) if not the right tool.
	VerifyOutput(stdout, stderr string) (version string, verified bool)

	// DisplayName returns the human-readable name for reporting.
	DisplayName() string

	// App returns the application identifier.
	App() string
}

// probeAndVerify runs a CLI tool discoverer through the standard
// lookup → execute → verify → emit pipeline.
func probeAndVerify(ctx context.Context, verifier CLIToolVerifier, handler AIToolHandlerFn) error {
	for _, name := range verifier.BinaryNames() {
		binPath, err := exec.LookPath(name)
		if err != nil {
			continue
		}

		probeCtx, cancel := context.WithTimeout(ctx, cliProbeTimeout)
		defer cancel()

		var stdout, stderr bytes.Buffer

		cmd := exec.CommandContext(probeCtx, binPath, verifier.VerifyArgs()...)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err = cmd.Run()
		if err != nil {
			continue
		}

		version, verified := verifier.VerifyOutput(stdout.String(), stderr.String())
		if !verified {
			continue
		}

		tool := &AITool{
			Name:       verifier.DisplayName(),
			Type:       AIToolTypeCLITool,
			Scope:      AIToolScopeSystem,
			App:        verifier.App(),
			ConfigPath: binPath,
		}
		tool.ID = generateID(tool.App, string(tool.Type), string(tool.Scope), tool.Name, tool.ConfigPath)
		tool.SourceID = generateSourceID(tool.App, tool.ConfigPath)

		if version != "" {
			tool.SetMeta("binary.version", version)
		}
		tool.SetMeta("binary.path", binPath)
		tool.SetMeta("binary.verified", true)

		return handler(tool)
	}

	return nil
}

// cliToolDiscoverer wraps a CLIToolVerifier as an AIToolReader.
type cliToolDiscoverer struct {
	verifier CLIToolVerifier
	config   DiscoveryConfig
}

func (d *cliToolDiscoverer) Name() string { return d.verifier.DisplayName() + " CLI" }
func (d *cliToolDiscoverer) App() string  { return d.verifier.App() }
func (d *cliToolDiscoverer) EnumTools(ctx context.Context, handler AIToolHandlerFn) error {
	// CLI tools are system-scoped; skip when system scope is not enabled
	if !d.config.ScopeEnabled(AIToolScopeSystem) {
		return nil
	}
	return probeAndVerify(ctx, d.verifier, handler)
}
