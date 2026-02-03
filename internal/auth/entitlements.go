package auth

import (
	"context"
	"fmt"
	"sync"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	v11 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/vet/pkg/common/logger"
)

type Entitlement struct {
	Feature v11.Feature
	Limit   int64
}

// entitlementsManager manages entitlements caching and API calls
type entitlementsManager struct {
	mu           sync.RWMutex
	loaded       bool
	entitlements []Entitlement
	tenantID     string
}

// Global instance of the entitlements manager
var globalEntitlementsManager = &entitlementsManager{}

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

	cachedEntitlements := make([]Entitlement, len(response.GetEntitlements()))
	for i, entitlement := range response.GetEntitlements() {
		cachedEntitlements[i] = Entitlement{
			Feature: entitlement.Entitlement.Feature,
			Limit:   entitlement.Entitlement.Limit,
		}
	}

	// Cache the entitlements
	globalEntitlementsManager.mu.Lock()
	defer globalEntitlementsManager.mu.Unlock()

	globalEntitlementsManager.loaded = true
	globalEntitlementsManager.entitlements = cachedEntitlements

	logger.Debugf("Successfully loaded %d entitlements for tenant: %s",
		len(globalEntitlementsManager.entitlements), globalEntitlementsManager.tenantID)

	return nil
}

// HasEntitlements checks if the current tenant has the specified entitlements
// This always depends on cached entitlements and never calls the API directly
func HasEntitlements(entitlementsFeatures ...v11.Feature) bool {
	globalEntitlementsManager.mu.RLock()
	defer globalEntitlementsManager.mu.RUnlock()

	if !globalEntitlementsManager.loaded {
		logger.Debugf("Entitlements not loaded, returning false")
		return false
	}

	// Check if all requested entitlements are available
	for _, requestedEntitlementFeature := range entitlementsFeatures {
		found := false
		for _, availableEntitlement := range globalEntitlementsManager.entitlements {
			if availableEntitlement.Feature == requestedEntitlementFeature {
				found = true
				break
			}
		}
		if !found {
			logger.Debugf("Entitlement %s not found for tenant", requestedEntitlementFeature)
			return false
		}
	}

	logger.Debugf("All requested entitlements available for tenant")
	return true
}
