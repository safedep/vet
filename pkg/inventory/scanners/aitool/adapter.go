package aitool

import (
	"context"
	"errors"
	"fmt"

	"github.com/safedep/vet/pkg/aitool"
	"github.com/safedep/vet/pkg/inventory"
)

// scannerName is the stable, log-safe identifier exposed via Scanner.Name.
const scannerName = "aitool"

// adapter implements inventory.Scanner by delegating discovery to an
// aitool.Registry and translating each emitted aitool.AITool into a
// wire-decoupled inventory.Item.
//
// Construction takes a registry rather than a factory so that tests can
// inject a registry seeded with deterministic fakes, and so that the cmd
// layer can swap in aitool.DefaultRegistry without owning the wiring.
type adapter struct {
	registry *aitool.Registry
}

// New constructs an inventory.Scanner that discovers AI tools, MCP
// servers, coding agents, and AI extensions via the supplied aitool
// registry. registry must be non-nil.
func New(registry *aitool.Registry) inventory.Scanner {
	if registry == nil {
		panic("inventory/scanners/aitool: registry must not be nil")
	}
	return &adapter{registry: registry}
}

// Name returns the stable scanner identifier used in logs and ScanError.
func (a *adapter) Name() string {
	return scannerName
}

// Scan walks every discoverer registered in the underlying aitool
// registry, translates each AITool to an Item, and forwards to emit.
//
// emit's error is propagated back up so the orchestrator can stop the
// scan when the consumer requests early termination (e.g. context
// cancellation surfaced through the emit closure).
func (a *adapter) Scan(ctx context.Context, cfg inventory.ScanConfig, emit inventory.EmitFunc) error {
	if emit == nil {
		return errors.New("inventory/scanners/aitool: emit must not be nil")
	}

	discoveryCfg, err := toDiscoveryConfig(cfg)
	if err != nil {
		return fmt.Errorf("aitool scanner: build discovery config: %w", err)
	}

	return a.registry.Discover(ctx, discoveryCfg, func(t *aitool.AITool) error {
		if t == nil {
			return nil
		}
		return emit(translate(t))
	})
}

// toDiscoveryConfig adapts an inventory.ScanConfig to an
// aitool.DiscoveryConfig. Nil scopes preserve aitool's "all scopes"
// semantics; an explicit (possibly empty) scope list is converted to a
// DiscoveryScope. An unknown scope value bubbles up the underlying
// error so the orchestrator records a scanner_failed event.
func toDiscoveryConfig(cfg inventory.ScanConfig) (aitool.DiscoveryConfig, error) {
	out := aitool.DiscoveryConfig{
		HomeDir:    cfg.HomeDir,
		ProjectDir: cfg.ProjectDir,
	}
	if cfg.Scopes == nil {
		return out, nil
	}

	scopes, err := convertScopes(cfg.Scopes)
	if err != nil {
		return aitool.DiscoveryConfig{}, err
	}
	scope, err := aitool.NewDiscoveryScope(scopes...)
	if err != nil {
		return aitool.DiscoveryConfig{}, err
	}
	out.Scope = scope
	return out, nil
}

// convertScopes maps inventory.Scope values to their aitool equivalents.
// Unknown scopes return an error so the caller can attribute the failure
// to the aitool scanner.
func convertScopes(in []inventory.Scope) ([]aitool.AIToolScope, error) {
	out := make([]aitool.AIToolScope, 0, len(in))
	for _, s := range in {
		switch s {
		case inventory.ScopeSystem:
			out = append(out, aitool.AIToolScopeSystem)
		case inventory.ScopeProject:
			out = append(out, aitool.AIToolScopeProject)
		default:
			return nil, fmt.Errorf("unsupported scope: %d", s)
		}
	}
	return out, nil
}
