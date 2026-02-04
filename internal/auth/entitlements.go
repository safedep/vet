package auth

import (
	"context"
	"fmt"
	"sync"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	v1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"

	"github.com/safedep/vet/pkg/common/logger"
)

// entitlementsManager manages entitlements caching and API calls
type entitlementsManager struct {
	mu           sync.RWMutex
	loaded       bool
	entitlements map[v1.Feature]*v1.Entitlement
}

// Global instance of the entitlements manager
var globalEntitlementsManager = &entitlementsManager{}

// store caches the entitlements, adding them to the existing map while avoiding duplicates
func (g *entitlementsManager) store(entitlements []*v1.Entitlement) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Initialize map if not already done
	if !g.loaded || g.entitlements == nil {
		g.loaded = true
		g.entitlements = make(map[v1.Feature]*v1.Entitlement)
	}

	// Add entitlements to the map (automatically avoids duplicates)
	for _, entitlement := range entitlements {
		// Store pointer to avoid copying mutex lock from protocolbuffer object
		g.entitlements[entitlement.Feature] = entitlement
	}

	logger.Debugf("Successfully added new entitlements (total: %d)", len(g.entitlements))
}

// hasEntitlement checks if the entitlements manager has the specified entitlement
func (g *entitlementsManager) hasEntitlement(entitlementsFeatures ...v1.Feature) bool {
	if !g.loaded {
		logger.Debugf("Entitlements not loaded, please call LoadEntitlements() first, returning false")
		return false
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, feature := range entitlementsFeatures {
		if _, ok := g.entitlements[feature]; ok {
			return true
		}
	}
	logger.Debugf("Entitlements not found for tenant")
	return false
}

// LoadEntitlements loads and caches entitlements for the current tenant
// If this fails, then no credential is available and the app should switch to community mode
func LoadEntitlements() error {
	logger.Debugf("Loading entitlements for tenant")

	client, err := SyncClientConnection("vet-entitlements")
	if err != nil {
		return fmt.Errorf("failed to create sync client connection: %w", err)
	}

	toolServiceClient := controltowerv1grpc.NewToolServiceClient(client)
	response, err := toolServiceClient.GetEntitlementsForTool(context.Background(), &controltowerv1.GetEntitlementsForToolRequest{})
	if err != nil {
		return fmt.Errorf("failed to get entitlements for tool: %w", err)
	}

	if response == nil {
		return fmt.Errorf("failed to get entitlements for tool: response is nil")
	}

	entitlementsToCache := make([]*v1.Entitlement, 0, len(response.GetEntitlements()))
	for _, entitlement := range response.GetEntitlements() {
		if entitlement.Entitlement == nil {
			continue
		}
		entitlementsToCache = append(entitlementsToCache, &v1.Entitlement{
			Feature:    entitlement.Entitlement.Feature,
			Limit:      entitlement.Entitlement.Limit,
			Attributes: entitlement.Entitlement.Attributes,
		})
	}

	// Cache the entitlements
	globalEntitlementsManager.store(entitlementsToCache)
	return nil
}

// HasEntitlements checks if the current tenant has the specified entitlements
// This always depends on cached entitlements and never calls the API directly
func HasEntitlements(entitlementsFeatures ...v1.Feature) bool {
	return globalEntitlementsManager.hasEntitlement(entitlementsFeatures...)
}
