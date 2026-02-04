package auth

import (
	"context"
	"testing"

	v1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockToolServiceClient is a mock for the ToolServiceClient
type MockToolServiceClient struct {
	mock.Mock
}

func (m *MockToolServiceClient) GetEntitlementsForTool(ctx context.Context, req *controltowerv1.GetEntitlementsForToolRequest, opts ...[]interface{}) (*controltowerv1.GetEntitlementsForToolResponse, error) {
	args := m.Called(ctx, req)
	if resp := args.Get(0); resp != nil {
		return resp.(*controltowerv1.GetEntitlementsForToolResponse), args.Error(1)
	}
	return nil, args.Error(1)
}

// MockSyncClientConnectionFunc is a mock for SyncClientConnection function
type MockSyncClientConnectionFunc struct {
	mock.Mock
}

func (m *MockSyncClientConnectionFunc) Execute(name string) (interface{}, error) {
	args := m.Called(name)
	if args.Get(0) != nil {
		return args.Get(0), args.Error(1)
	}
	return nil, args.Error(1)
}

func withGlobalEntitlementsManager(t *testing.T, fn func() *entitlementsManager) {
	oldManager := globalEntitlementsManager
	t.Cleanup(func() {
		globalEntitlementsManager = oldManager
	})

	globalEntitlementsManager = fn()
}

func TestEntitlementsManager_cache(t *testing.T) {
	t.Run("should cache entitlements successfully", func(t *testing.T) {
		manager := &entitlementsManager{}
		entitlements := []*v1.Entitlement{
			{Feature: v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING},
			{Feature: v1.Feature_FEATURE_ENTERPRISE_DASHBOARD},
			{Feature: v1.Feature_FEATURE_ENTERPRISE_SUPPORT},
			{Feature: v1.Feature_FEATURE_SQL_QUERY},
			{Feature: v1.Feature_FEATURE_STANDARD_DASHBOARD},
		}

		manager.store(entitlements)

		assert.True(t, manager.loaded)
		assert.Equal(t, len(entitlements), len(manager.entitlements))
		for _, expected := range entitlements {
			assert.Equal(t, expected, manager.entitlements[expected.Feature])
		}
	})

	t.Run("should handle empty entitlements list", func(t *testing.T) {
		manager := &entitlementsManager{}
		entitlements := []*v1.Entitlement{}

		manager.store(entitlements)

		assert.True(t, manager.loaded)
		assert.Equal(t, len(entitlements), len(manager.entitlements))
		assert.Len(t, manager.entitlements, 0)
	})

	t.Run("should overwrite existing entitlements", func(t *testing.T) {
		manager := &entitlementsManager{}
		initialEntitlements := []*v1.Entitlement{
			{Feature: v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING},
		}
		manager.store(initialEntitlements)

		newEntitlements := []*v1.Entitlement{
			{Feature: v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING},
			{Feature: v1.Feature_FEATURE_ENTERPRISE_DASHBOARD},
		}
		manager.store(newEntitlements)

		assert.True(t, manager.loaded)
		assert.Equal(t, len(newEntitlements), len(manager.entitlements))
		for _, expected := range newEntitlements {
			assert.Equal(t, expected, manager.entitlements[expected.Feature])
		}
	})

	t.Run("should add new entitlements while avoiding duplicates on multiple calls", func(t *testing.T) {
		manager := &entitlementsManager{}

		// First call with initial entitlements
		firstEntitlements := []*v1.Entitlement{
			{Feature: v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING},
			{Feature: v1.Feature_FEATURE_ENTERPRISE_DASHBOARD},
		}
		manager.store(firstEntitlements)

		assert.Len(t, manager.entitlements, 2)
		assert.True(t, manager.hasEntitlement(v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING))
		assert.True(t, manager.hasEntitlement(v1.Feature_FEATURE_ENTERPRISE_DASHBOARD))

		// Second call with mixed new and existing entitlements
		secondEntitlements := []*v1.Entitlement{
			{Feature: v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING}, // duplicate
			{Feature: v1.Feature_FEATURE_SQL_QUERY},                         // new
			{Feature: v1.Feature_FEATURE_ENTERPRISE_SUPPORT},                // new
		}
		manager.store(secondEntitlements)

		// Should have 4 unique entitlements total
		assert.Len(t, manager.entitlements, 4)
		assert.True(t, manager.hasEntitlement(v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING))
		assert.True(t, manager.hasEntitlement(v1.Feature_FEATURE_ENTERPRISE_DASHBOARD))
		assert.True(t, manager.hasEntitlement(v1.Feature_FEATURE_SQL_QUERY))
		assert.True(t, manager.hasEntitlement(v1.Feature_FEATURE_ENTERPRISE_SUPPORT))

		// Third call with only duplicates
		thirdEntitlements := []*v1.Entitlement{
			{Feature: v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING}, // duplicate
			{Feature: v1.Feature_FEATURE_SQL_QUERY},                         // duplicate
		}
		manager.store(thirdEntitlements)

		// Should still have 4 unique entitlements
		assert.Len(t, manager.entitlements, 4)
		assert.True(t, manager.hasEntitlement(v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING))
		assert.True(t, manager.hasEntitlement(v1.Feature_FEATURE_ENTERPRISE_DASHBOARD))
		assert.True(t, manager.hasEntitlement(v1.Feature_FEATURE_SQL_QUERY))
		assert.True(t, manager.hasEntitlement(v1.Feature_FEATURE_ENTERPRISE_SUPPORT))
	})
}

func TestEntitlementsManager_hasEntitlement(t *testing.T) {
	t.Run("should return true for existing entitlement", func(t *testing.T) {
		manager := &entitlementsManager{}
		entitlements := []*v1.Entitlement{
			{Feature: v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING},
			{Feature: v1.Feature_FEATURE_ENTERPRISE_DASHBOARD},
		}
		manager.store(entitlements)

		result := manager.hasEntitlement(v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING)

		assert.True(t, result)
	})

	t.Run("should return true for any of multiple entitlements", func(t *testing.T) {
		manager := &entitlementsManager{}
		entitlements := []*v1.Entitlement{
			{Feature: v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING},
		}
		manager.store(entitlements)

		result := manager.hasEntitlement(
			v1.Feature_FEATURE_ENTERPRISE_DASHBOARD,
			v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING,
		)

		assert.True(t, result)
	})

	t.Run("should return false for non-existing entitlement", func(t *testing.T) {
		manager := &entitlementsManager{}
		entitlements := []*v1.Entitlement{
			{Feature: v1.Feature_FEATURE_ENTERPRISE_DASHBOARD},
		}
		manager.store(entitlements)

		result := manager.hasEntitlement(v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING)

		assert.False(t, result)
	})

	t.Run("should return false for multiple non-existing entitlements", func(t *testing.T) {
		manager := &entitlementsManager{}
		entitlements := []*v1.Entitlement{
			{Feature: v1.Feature_FEATURE_ENTERPRISE_DASHBOARD},
		}
		manager.store(entitlements)

		result := manager.hasEntitlement(
			v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING,
			v1.Feature_FEATURE_SQL_QUERY,
		)

		assert.False(t, result)
	})

	t.Run("should return false when no entitlements are cached", func(t *testing.T) {
		manager := &entitlementsManager{}

		result := manager.hasEntitlement(v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING)

		assert.False(t, result)
	})

	t.Run("should handle empty entitlements list", func(t *testing.T) {
		manager := &entitlementsManager{}
		entitlements := []*v1.Entitlement{}
		manager.store(entitlements)

		result := manager.hasEntitlement(v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING)

		assert.False(t, result)
	})

	t.Run("should be thread-safe for concurrent reads", func(t *testing.T) {
		manager := &entitlementsManager{}
		entitlements := []*v1.Entitlement{
			{Feature: v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING},
		}
		manager.store(entitlements)

		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func() {
				result := manager.hasEntitlement(v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING)
				assert.True(t, result)
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

func TestHasEntitlements(t *testing.T) {
	t.Run("should return false when entitlements not loaded", func(t *testing.T) {
		manager := &entitlementsManager{loaded: false}
		withGlobalEntitlementsManager(t, func() *entitlementsManager {
			return manager
		})

		result := HasEntitlements(v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING)

		assert.False(t, result)
	})

	t.Run("should delegate to global manager when loaded", func(t *testing.T) {
		manager := &entitlementsManager{}
		entitlements := []*v1.Entitlement{
			{Feature: v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING},
		}
		manager.store(entitlements)

		withGlobalEntitlementsManager(t, func() *entitlementsManager {
			return manager
		})

		result := HasEntitlements(v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING)

		assert.True(t, result)
	})

	t.Run("should return false for non-existing entitlement when loaded", func(t *testing.T) {
		manager := &entitlementsManager{}
		entitlements := []*v1.Entitlement{
			{Feature: v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING},
		}
		manager.store(entitlements)

		withGlobalEntitlementsManager(t, func() *entitlementsManager {
			return manager
		})

		result := HasEntitlements(v1.Feature_FEATURE_ENTERPRISE_DASHBOARD)

		assert.False(t, result)
	})

	t.Run("should handle multiple entitlements check", func(t *testing.T) {
		manager := &entitlementsManager{}
		entitlements := []*v1.Entitlement{
			{Feature: v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING},
			{Feature: v1.Feature_FEATURE_ENTERPRISE_DASHBOARD},
		}
		manager.store(entitlements)

		withGlobalEntitlementsManager(t, func() *entitlementsManager {
			return manager
		})

		result := HasEntitlements(
			v1.Feature_FEATURE_ENTERPRISE_DASHBOARD,
			v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING,
		)

		assert.True(t, result)
	})

	t.Run("should return false for empty entitlements list when loaded", func(t *testing.T) {
		manager := &entitlementsManager{}
		entitlements := []*v1.Entitlement{}
		manager.store(entitlements)

		withGlobalEntitlementsManager(t, func() *entitlementsManager {
			return manager
		})

		result := HasEntitlements(v1.Feature_FEATURE_ACTIVE_MALICIOUS_PACKAGE_SCANNING)

		assert.False(t, result)
	})
}
