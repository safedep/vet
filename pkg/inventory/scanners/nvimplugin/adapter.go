// Package nvimplugin is an inventory.Scanner that discovers Neovim plugins
// installed by supported plugin managers (currently lazy.nvim). Each plugin
// is emitted as an inventory.Item with Kind KindIDEExtension, App "neovim",
// and plugin.* metadata identifying its upstream repository.
package nvimplugin

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/safedep/vet/pkg/inventory"
)

const scannerName = "nvim-plugin"

type adapter struct {
	managers []Manager
}

// New constructs the Neovim plugin scanner with the shipped manager set.
func New() inventory.Scanner {
	return newAdapter(defaultManagers()...)
}

// newAdapter builds an adapter over an explicit manager set (tests inject
// fakes).
func newAdapter(managers ...Manager) *adapter {
	return &adapter{managers: managers}
}

func (a *adapter) Name() string { return scannerName }

// discovered pairs a plugin with its manager so translate can record
// plugin.manager after the cross-manager merge.
type discovered struct {
	plugin  Plugin
	manager string
}

// Scan resolves the Neovim environment, runs every manager, and emits one
// item per plugin in deterministic name order. Neovim plugins are
// system-scoped, so the scan is a no-op unless system scope is enabled.
// Per-manager failures are aggregated with errors.Join and returned after
// every discoverable plugin is emitted, so one broken manager cannot
// suppress another's results.
func (a *adapter) Scan(ctx context.Context, cfg inventory.ScanConfig, emit inventory.EmitFunc) error {
	if !cfg.ScopeEnabled(inventory.ScopeSystem) {
		return nil
	}

	env, err := resolveEnv(cfg)
	if err != nil {
		return fmt.Errorf("resolve neovim environment: %w", err)
	}

	var (
		items []discovered
		errs  []error
	)
	for _, m := range a.managers {
		plugins, derr := m.Discover(ctx, env)
		if derr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.Name(), derr))
		}
		for _, p := range plugins {
			items = append(items, discovered{plugin: p, manager: m.Name()})
		}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].plugin.Name != items[j].plugin.Name {
			return items[i].plugin.Name < items[j].plugin.Name
		}
		return items[i].manager < items[j].manager
	})

	for _, d := range items {
		if err := emit(translate(d.manager, d.plugin)); err != nil {
			return err
		}
	}

	return errors.Join(errs...)
}
