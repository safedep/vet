package agent

import (
	"context"
	"sync"

	"github.com/cloudwego/eino/schema"
)

type simpleMemory struct {
	mutex        sync.RWMutex
	interactions []*schema.Message
}

var _ Memory = (*simpleMemory)(nil)

func NewSimpleMemory() (*simpleMemory, error) {
	return &simpleMemory{
		interactions: make([]*schema.Message, 0),
	}, nil
}

func (m *simpleMemory) AddInteraction(ctx context.Context, interaction *schema.Message) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.interactions = append(m.interactions, interaction)

	return nil
}

func (m *simpleMemory) GetInteractions(ctx context.Context) ([]*schema.Message, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.interactions, nil
}

func (m *simpleMemory) Clear(ctx context.Context) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.interactions = make([]*schema.Message, 0)
	return nil
}
