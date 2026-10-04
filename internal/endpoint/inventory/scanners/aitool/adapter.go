// Package aitool adapts the aitool discovery layer to the inventory
// producer pipeline.
package aitool

import (
	"context"
	"errors"
	"fmt"

	"github.com/safedep/vet/v2/internal/endpoint/aitool"
	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

// scannerName is the stable, log-safe identifier exposed via Scanner.Name.
const scannerName = "aitool"

// adapter implements inventory.Scanner by delegating discovery to an
// aitool.Registry.
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
// registry and forwards each item to emit.
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

	return a.registry.Discover(ctx, discoveryCfg, func(it *inventory.Item) error {
		if it == nil {
			return nil
		}
		return emit(it)
	})
}

// toDiscoveryConfig adapts an inventory.ScanConfig to an
// aitool.DiscoveryConfig. Nil scopes preserve aitool's "all scopes"
// semantics. An unknown scope value bubbles up the underlying error so
// the orchestrator records a scanner_failed event.
func toDiscoveryConfig(cfg inventory.ScanConfig) (aitool.DiscoveryConfig, error) {
	out := aitool.DiscoveryConfig{
		HomeDir:    cfg.HomeDir,
		ProjectDir: cfg.ProjectDir,
	}
	if cfg.Scopes == nil {
		return out, nil
	}

	scope, err := aitool.NewDiscoveryScope(cfg.Scopes...)
	if err != nil {
		return aitool.DiscoveryConfig{}, err
	}
	out.Scope = scope
	return out, nil
}
