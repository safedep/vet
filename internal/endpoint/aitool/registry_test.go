package aitool

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

type mockReader struct {
	name  string
	app   string
	tools []*inventory.Item
}

func (m *mockReader) Name() string { return m.name }
func (m *mockReader) App() string  { return m.app }
func (m *mockReader) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
	for _, tool := range m.tools {
		if err := handler(tool); err != nil {
			return err
		}
	}
	return nil
}

func TestRegistry_DiscoverCallsAllFactories(t *testing.T) {
	r := NewRegistry()

	r.Register("reader1", func(_ DiscoveryConfig) (AIToolReader, error) {
		return &mockReader{
			name: "reader1",
			app:  "host1",
			tools: []*inventory.Item{
				{Name: "tool1", App: "host1"},
			},
		}, nil
	})

	r.Register("reader2", func(_ DiscoveryConfig) (AIToolReader, error) {
		return &mockReader{
			name: "reader2",
			app:  "host2",
			tools: []*inventory.Item{
				{Name: "tool2", App: "host2"},
			},
		}, nil
	})

	var collected []*inventory.Item
	err := r.Discover(context.Background(), DiscoveryConfig{}, func(tool *inventory.Item) error {
		collected = append(collected, tool)
		return nil
	})

	require.NoError(t, err)
	assert.Len(t, collected, 2)
	assert.Equal(t, "tool1", collected[0].Name)
	assert.Equal(t, "tool2", collected[1].Name)
}

func TestRegistry_FactoryErrorSkipped(t *testing.T) {
	r := NewRegistry()

	r.Register("failing", func(_ DiscoveryConfig) (AIToolReader, error) {
		return nil, errors.New("factory error")
	})

	r.Register("working", func(_ DiscoveryConfig) (AIToolReader, error) {
		return &mockReader{
			name:  "working",
			app:   "host",
			tools: []*inventory.Item{{Name: "tool1"}},
		}, nil
	})

	var collected []*inventory.Item
	err := r.Discover(context.Background(), DiscoveryConfig{}, func(tool *inventory.Item) error {
		collected = append(collected, tool)
		return nil
	})

	require.NoError(t, err)
	assert.Len(t, collected, 1)
}

func TestRegistry_HandlerErrorPropagated(t *testing.T) {
	r := NewRegistry()

	r.Register("reader", func(_ DiscoveryConfig) (AIToolReader, error) {
		return &mockReader{
			name:  "reader",
			app:   "host",
			tools: []*inventory.Item{{Name: "tool1"}, {Name: "tool2"}},
		}, nil
	})

	handlerErr := errors.New("handler error")
	err := r.Discover(context.Background(), DiscoveryConfig{}, func(tool *inventory.Item) error {
		return handlerErr
	})

	assert.ErrorIs(t, err, handlerErr)
}

func TestRegistry_DeterministicOrder(t *testing.T) {
	r := NewRegistry()

	for i, name := range []string{"c", "a", "b"} {
		idx := i
		n := name
		r.Register(n, func(_ DiscoveryConfig) (AIToolReader, error) {
			return &mockReader{
				name:  n,
				app:   n,
				tools: []*inventory.Item{{Name: n, App: n, Metadata: map[string]string{"order": strconv.Itoa(idx)}}},
			}, nil
		})
	}

	var names []string
	err := r.Discover(context.Background(), DiscoveryConfig{}, func(tool *inventory.Item) error {
		names = append(names, tool.Name)
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, []string{"c", "a", "b"}, names, "should preserve registration order")
}
